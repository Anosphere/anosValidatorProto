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
	userPrivKeysCSV := flag.String("userPrivKeys", "", "CSV *or* path to .csv of 50 USER_PRIVATE_KEY values (hex)")
	userHexesCSV := flag.String("userHexes", "", "CSV *or* path to .csv of 50 USER_HEX values (hex pubkeys)")
	ridsCSV := flag.String("rids", "", "CSV *or* path to .csv of 50 receivable IDs (hex)")
	flag.Parse()

	if *userPrivKeysCSV == "" || *userHexesCSV == "" || *ridsCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --userPrivKeys, --userHexes, and --rids are required")
		os.Exit(1)
	}

	userPrivKeyHexes := loadHexList(*userPrivKeysCSV)
	userHexes := loadHexList(*userHexesCSV)
	ridHexes := loadHexList(*ridsCSV)

	const n = 50
	if len(userPrivKeyHexes) < n || len(userHexes) < n || len(ridHexes) < n {
		fmt.Fprintf(os.Stderr, "ERROR: expected at least %d entries in each list; got priv=%d pub=%d rid=%d\n",
			n, len(userPrivKeyHexes), len(userHexes), len(ridHexes))
		os.Exit(1)
	}

	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	if len(validatorUrlList) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	baseURL := validatorUrlList[0]

	pollEvery := 200 * time.Millisecond
	maxWait := 30 * time.Second

	type acctInfo struct {
		i    int
		pub  []byte
		priv ed25519.PrivateKey
		rid  []byte
	}

	accts := make([]acctInfo, 0, n)
	for i := 0; i < n; i++ {
		priv, err := parsePrivKey(strings.TrimSpace(userPrivKeyHexes[i]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad priv key hex at index %d: %v\n", i, err)
			os.Exit(1)
		}

		pubBytes, err := hex.DecodeString(strings.TrimSpace(userHexes[i]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad pub hex at index %d: %v\n", i, err)
			os.Exit(1)
		}
		ridBytes, err := hex.DecodeString(strings.TrimSpace(ridHexes[i]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: bad rid hex at index %d: %v\n", i, err)
			os.Exit(1)
		}

		accts = append(accts, acctInfo{
			i:    i,
			pub:  pubBytes,
			priv: priv,
			rid:  ridBytes,
		})
	}

	var wg sync.WaitGroup
	errCh := make(chan error, n)

	start := time.Now()
	log.Printf("Starting %d concurrent RECEIVEs against %s", n, baseURL)

	for _, a := range accts {
		wg.Add(1)
		go func(a acctInfo) {
			defer wg.Done()

			// Optional: wait until receivable appears (avoids submit racing before gossip)
			_ = waitForReceivable(baseURL, a.pub, a.rid, pollEvery, maxWait)

			// Fetch Bob state
			st := mustGetAccount(baseURL, a.pub)

			recv := &pb.Tx{
				Type:    pb.TxType_TX_TYPE_RECEIVE,
				Account: &pb.AccountId{V: a.pub},
				Prev:    &pb.Hash32{V: st.Head.GetV()},
				Seq:     st.Seq + 1,
				Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
					ReceivableId: &pb.Hash32{V: a.rid},
					AccountClass: pb.AccountClass_ACCOUNT_CLASS_HOT,
				}},
			}

			signTx(recv, a.priv)
			mustSubmit(baseURL, recv)

			// Wait for commit
			waitForSeqAtLeast(baseURL, a.pub, st.Seq+1, pollEvery, maxWait)

			log.Printf("[%02d] RECEIVE OK pub=%s rid=%s",
				a.i,
				hex.EncodeToString(a.pub)[:16],
				hex.EncodeToString(a.rid)[:16],
			)
		}(a)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			log.Printf("ERROR: %v", err)
		}
	}

	log.Printf("Done in %s", time.Since(start))
}

// ---- same helpers as your file below ----

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
	fmt.Printf("acct=%s bal_units=%d bal_anos=%.6f seq=%d head=%s\n",
		hex.EncodeToString(acct)[:8],
		resp.State.Balance,
		float64(resp.State.Balance)/float64(core.UnitsPerAnos),
		resp.State.Seq,
		hex.EncodeToString(resp.State.Head.V)[:8],
	)
	return resp.State
}

func mustListReceivables(baseURL string, acct []byte) []*pb.Receivable {
	req := &pb.ListReceivablesRequest{Account: &pb.AccountId{V: acct}, IncludeClaimed: false}
	resp := &pb.ListReceivablesResponse{}
	if err := postProto(baseURL+"/receivables", req, resp); err != nil {
		panic(err)
	}
	if !resp.Ok {
		panic(fmt.Sprintf("receivables failed: %v", resp.Error))
	}
	return resp.Receivables
}

func waitForReceivable(baseURL string, acct []byte, wantRID []byte, pollEvery, maxWait time.Duration) []byte {
	deadline := time.Now().Add(maxWait)
	for {
		recs := mustListReceivables(baseURL, acct)
		for _, r := range recs {
			if r != nil && r.Id != nil && bytesEq(r.Id.V, wantRID) {
				return r.Id.V
			}
		}
		if len(recs) > 0 && recs[0] != nil && recs[0].Id != nil {
			return recs[0].Id.V
		}
		if time.Now().After(deadline) {
			panic("timed out waiting for receivable")
		}
		time.Sleep(pollEvery)
	}
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

// loadHexList accepts either:
//  1. a CSV string (comma-separated), or
//  2. a path to a .csv file containing newline-separated values, comma-separated values,
//     or any mixture of commas/newlines.
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
		// Treat newlines as commas, then use existing CSV splitter (trims empties).
		return splitCSV(strings.ReplaceAll(string(b), "\n", ","))
	}
	return splitCSV(arg)
}

// parsePrivKey supports several formats:
//   - 64 hex chars (32-byte seed): ed25519.NewKeyFromSeed
//   - 128 hex chars (64-byte ed25519 private key): used directly
//   - 192 hex chars (private||public concatenated): takes the first 128 hex chars
func parsePrivKey(privHex string) (ed25519.PrivateKey, error) {
	privHex = strings.TrimSpace(privHex)
	privHex = strings.TrimPrefix(privHex, "0x")
	if len(privHex) == 192 {
		privHex = privHex[:128]
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, err
	}
	switch len(privBytes) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(privBytes), nil
	case ed25519.PrivateKeySize:
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
