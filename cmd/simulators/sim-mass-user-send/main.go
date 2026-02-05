// cmd/simulators/sim-mass-user-send/main.go
package main

import (
	"anos/internal/core"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	// Inputs: sender lists
	publicCSV := flag.String("public", "", "CSV string or path to public.csv (newline or comma separated hex pubkeys)")
	privateCSV := flag.String("private", "", "CSV string or path to private.csv (newline or comma separated hex private keys; supports 64/128/192 hex per entry)")
	flag.Parse()

	if *publicCSV == "" || *privateCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --public and --private are required")
		os.Exit(1)
	}

	// Validator URL
	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	if len(validatorUrlList) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	baseURL := validatorUrlList[2]

	// Recipient: USER_HEX
	toHex := getenv("USER_HEX", "")
	if strings.TrimSpace(toHex) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: USER_HEX is required (recipient pubkey hex)")
		os.Exit(1)
	}
	toPub, err := hex.DecodeString(strings.TrimSpace(toHex))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: bad USER_HEX %q: %v\n", toHex, err)
		os.Exit(1)
	}

	// Load senders
	pubHexes := loadHexList(*publicCSV)
	privHexes := loadHexList(*privateCSV)

	if len(pubHexes) == 0 || len(privHexes) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: empty sender lists: pub=%d priv=%d\n", len(pubHexes), len(privHexes))
		os.Exit(1)
	}

	// Pair by index (assumes public.csv and private.csv are in the same order).
	n := len(pubHexes)
	if len(privHexes) < n {
		n = len(privHexes)
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: no usable sender pairs")
		os.Exit(1)
	}

	type sender struct {
		i    int
		pub  []byte
		priv ed25519.PrivateKey
	}
	senders := make([]sender, 0, n)

	for i := 0; i < n; i++ {
		pub, err := hex.DecodeString(strings.TrimSpace(pubHexes[i]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad pub hex at index %d: %v\n", i, err)
			os.Exit(1)
		}
		priv, err := parsePrivKey(privHexes[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad priv hex at index %d: %v\n", i, err)
			os.Exit(1)
		}

		senders = append(senders, sender{
			i:    i,
			pub:  pub,
			priv: priv,
		})
	}

	// Amount: 100 coins
	amount := uint64(1 * core.UnitsPerAnos)
	fee := core.ExpectedFee(amount)

	log.Printf("Sending %0.6f coins (+fee %0.6f) from %d accounts to USER_HEX=%s via %s",
		float64(amount)/float64(core.UnitsPerAnos),
		float64(fee)/float64(core.UnitsPerAnos),
		len(senders),
		hex.EncodeToString(toPub),
		baseURL,
	)

	pollEvery := 200 * time.Millisecond
	maxWait := 30 * time.Second

	var wg sync.WaitGroup
	type result struct {
		i    int
		pub  string
		txid string
		rid  string
		err  error
	}
	resCh := make(chan result, len(senders))

	start := time.Now()

	for _, s := range senders {
		wg.Add(1)
		go func(s sender) {
			defer wg.Done()

			// Skip self-send if sender==recipient (optional but usually desired)
			if bytesEq(s.pub, toPub) {
				resCh <- result{i: s.i, pub: hex.EncodeToString(s.pub)[:16], err: fmt.Errorf("skipped: sender==recipient")}
				return
			}

			// Get sender state
			st := mustGetAccount(baseURL, s.pub)

			// Quick client-side balance check (avoid submitting a tx that will never commit)
			need := amount + fee
			if st.Balance < need {
				resCh <- result{
					i:   s.i,
					pub: hex.EncodeToString(s.pub)[:16],
					err: fmt.Errorf("insufficient funds: balance=%0.6f need=%0.6f",
						float64(st.Balance)/float64(core.UnitsPerAnos),
						float64(need)/float64(core.UnitsPerAnos),
					),
				}
				return
			}

			send := &pb.Tx{
				Type:    pb.TxType_TX_TYPE_SEND,
				Account: &pb.AccountId{V: s.pub},
				Prev:    &pb.Hash32{V: st.Head.GetV()},
				Seq:     st.Seq + 1,
				Body: &pb.Tx_Send{Send: &pb.TxBodySend{
					To:     &pb.AccountId{V: toPub},
					Amount: amount,
					Fee:    fee,
				}},
			}

			signTx(send, s.priv)

			// Set ReceivableId deterministically from txid (optional, but consistent with your other simulators)
			txid, _ := crypto.TxID(send)
			rid := crypto.ReceivableIDFromTxID(txid)
			send.GetSend().ReceivableId = &pb.Hash32{V: rid[:]}

			// Submit + wait for commit
			mustSubmit(baseURL, send)
			waitForSeqAtLeast(baseURL, s.pub, send.Seq, pollEvery, maxWait)

			resCh <- result{
				i:    s.i,
				pub:  hex.EncodeToString(s.pub)[:16],
				txid: hex.EncodeToString(txid[:])[:16],
				rid:  hex.EncodeToString(rid[:])[:16],
				err:  nil,
			}
		}(s)
	}

	wg.Wait()
	close(resCh)

	ok := 0
	fail := 0

	for r := range resCh {
		if r.err != nil {
			fail++
			log.Printf("[%02d] SEND FAIL from=%s err=%v", r.i, r.pub, r.err)
			continue
		}
		ok++
		log.Printf("[%02d] SEND OK   from=%s txid=%s rid=%s", r.i, r.pub, r.txid, r.rid)
	}

	log.Printf("Done in %s. ok=%d fail=%d", time.Since(start), ok, fail)
}

// ---------------- helpers ----------------

func signTx(tx *pb.Tx, priv ed25519.PrivateKey) {
	msgHash, _, err := crypto.MsgHash(tx)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, msgHash[:])
	tx.Sig = &pb.Sig64{V: sig}
}

func mustSubmit(baseURL string, tx *pb.Tx) {
	req := &pb.SubmitTxRequest{Tx: tx}
	resp := &pb.SubmitTxResponse{}
	if err := postProto(baseURL+"/submit", req, resp); err != nil {
		panic(err)
	}
	if !resp.Ok {
		panic(fmt.Sprintf("submit rejected: %v", resp.Error))
	}
}

func mustGetAccount(baseURL string, acct []byte) *pb.AccountState {
	req := &pb.GetAccountRequest{Account: &pb.AccountId{V: acct}}
	resp := &pb.GetAccountResponse{}
	if err := postProto(baseURL+"/account", req, resp); err != nil {
		panic(err)
	}
	if !resp.Ok || resp.State == nil {
		panic(fmt.Sprintf("account failed: %v", resp.Error))
	}
	return resp.State
}

func waitForSeqAtLeast(baseURL string, acct []byte, wantSeq uint64, pollEvery, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for {
		st := mustGetAccount(baseURL, acct)
		if st.Seq >= wantSeq {
			return
		}
		if time.Now().After(deadline) {
			panic("timed out waiting for seq bump")
		}
		time.Sleep(pollEvery)
	}
}

func postProto(url string, req proto.Message, resp proto.Message) error {
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(reqBytes))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Accept", "application/x-protobuf")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(httpResp.Body)
	_ = httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return proto.Unmarshal(body, resp)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadHexList(arg string) []string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil
	}
	if strings.HasSuffix(strings.ToLower(arg), ".csv") {
		b, err := os.ReadFile(arg)
		if err != nil {
			panic(err)
		}
		// allow newline-separated files too
		return splitCSV(strings.ReplaceAll(string(b), "\n", ","))
	}
	return splitCSV(arg)
}

func parsePrivKey(privHex string) (ed25519.PrivateKey, error) {
	privHex = strings.TrimSpace(privHex)
	privHex = strings.TrimPrefix(privHex, "0x")

	// private.csv in your repo is commonly priv(128 hex) + pub(64 hex) => 192 hex total
	if len(privHex) == 192 {
		privHex = privHex[:128]
	}

	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, err
	}

	switch len(privBytes) {
	case ed25519.SeedSize: // 32 bytes
		return ed25519.NewKeyFromSeed(privBytes), nil
	case ed25519.PrivateKeySize: // 64 bytes
		return ed25519.PrivateKey(privBytes), nil
	default:
		return nil, fmt.Errorf("unexpected privkey length: %d bytes (hex len=%d)", len(privBytes), len(privHex))
	}
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
