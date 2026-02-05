package main

import (
	"anos/internal/core"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	baseURL := validatorUrlList[0]

	// Alice keys (AccountId == pubkey bytes)
	alPriv, _ := hex.DecodeString(getenv("GENESIS_PRIVATE_KEY", ""))
	alHex := getenv("GENESIS_HEX", "")
	alPub, _ := hex.DecodeString(alHex)

	fmt.Println("Alice:", alHex)

	// Get recipient list:
	userHexesCSV := flag.String("userHexes", "", "CSV of 50 USER_HEX values (hex pubkeys)")
	flag.Parse()

	if *userHexesCSV == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --userHexes is required")
		os.Exit(1)
	}

	var userHexList []string

	if strings.HasSuffix(*userHexesCSV, ".csv") {
		data, err := os.ReadFile(*userHexesCSV)
		if err != nil {
			panic(err)
		}
		userHexList = splitCSV(strings.ReplaceAll(string(data), "\n", ","))
	} else {
		userHexList = splitCSV(*userHexesCSV)
	}

	log.Print((userHexList))

	const recipientCount = 50
	recipients := make([][]byte, 0, recipientCount)

	for _, h := range userHexList {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil {
			panic(fmt.Sprintf("bad USER_HEX_LIST entry %q: %v", h, err))
		}
		recipients = append(recipients, b)
		if len(recipients) >= recipientCount {
			break
		}
	}

	// Print recipients so you can reuse them / verify.
	fmt.Println("Recipients (hex pubkeys):")
	for i := 0; i < recipientCount; i++ {
		fmt.Printf("  [%02d] %s\n", i, hex.EncodeToString(recipients[i]))
	}

	// Amount + fee
	amount := uint64(100 * core.UnitsPerAnos)
	fee := core.ExpectedFee(amount)

	// Get Alice state once; we’ll refresh each iteration after submit.
	alState := mustGetAccount(baseURL, alPub)

	// Collect all receivable IDs in order
	rids := make([][32]byte, 0, recipientCount)

	for i := 0; i < recipientCount; i++ {
		toPub := recipients[i]

		// Build SEND tx from Alice to recipient
		send := &pb.Tx{
			Type:    pb.TxType_TX_TYPE_SEND,
			Account: &pb.AccountId{V: alPub},
			Prev:    &pb.Hash32{V: alState.Head.GetV()},
			Seq:     alState.Seq + 1,
			Body: &pb.Tx_Send{Send: &pb.TxBodySend{
				To:     &pb.AccountId{V: toPub},
				Amount: amount,
				Fee:    fee,
			}},
		}
		signTx(send, alPriv)

		// Derive txid + expected receivable_id (optional client-set)
		txid, _ := crypto.TxID(send)
		rid := crypto.ReceivableIDFromTxID(txid)
		send.GetSend().ReceivableId = &pb.Hash32{V: rid[:]}

		// Store rid (so we can print them all at the end)
		rids = append(rids, rid)

		// Submit
		mustSubmit(baseURL, send)

		fmt.Printf("Send %02d OK  to=%s  txid=%s  rid=%s\n",
			i,
			hex.EncodeToString(toPub)[:16],
			hex.EncodeToString(txid[:])[:16],
			hex.EncodeToString(rid[:])[:16],
		)

		// Wait until Alice seq is reflected, then refresh head/seq for the next tx.
		waitForSeqAtLeast(baseURL, alPub, send.Seq, 200*time.Millisecond, 30*time.Second)
		alState = mustGetAccount(baseURL, alPub)

		// Delay between sends (not after the last one)
		if i != recipientCount-1 {
			time.Sleep(1 * time.Second)
		}
	}

	// ---- Print all receivable IDs (end) ----
	fmt.Println("\nAll receivableIds (index -> hex):")
	for i, rid := range rids {
		fmt.Printf("  [%02d] %s\n", i, hex.EncodeToString(rid[:]))
	}

	// Also print as a CSV (useful for feeding into the receive50 tool)
	csvParts := make([]string, 0, len(rids))
	for _, rid := range rids {
		csvParts = append(csvParts, hex.EncodeToString(rid[:]))
	}
	fmt.Println("\nRID_LIST (CSV):")
	fmt.Println(strings.Join(csvParts, ","))
}

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

func mustKeypair() ([]byte, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func mustPOST(url string) {
	req, _ := http.NewRequest("POST", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		panic("POST failed: " + resp.Status)
	}
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

func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	if n <= 0 {
		return def
	}
	return n
}
