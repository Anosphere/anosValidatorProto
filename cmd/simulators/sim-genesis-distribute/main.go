package main

import (
	"anos/internal/core"
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))

	baseURL := validatorUrlList[0]

	pollEvery := 200 * time.Millisecond
	maxWait := 30 * time.Second

	// Generate Alice/Bob keys (AccountId == pubkey bytes)

	alPriv, _ := hex.DecodeString(getenv("GENESIS_PRIVATE_KEY", ""))
	boPriv, _ := hex.DecodeString(getenv("USER_PRIVATE_KEY", ""))

	alHex := getenv("GENESIS_HEX", "")
	boHex := getenv("USER_HEX", "")

	alPub, _ := hex.DecodeString(alHex)
	boPub, _ := hex.DecodeString(boHex)

	fmt.Println("Alice:", alHex)
	fmt.Println("Bob  :", boHex)

	// Fetch Alice state
	alState := mustGetAccount(baseURL, alPub)

	// Set Amount to Send
	amount := uint64(1000000 * core.UnitsPerAnos)

	// Calculate Fee
	fee := core.ExpectedFee(amount)

	// Build SEND tx from Alice to Bob
	send := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: alPub},
		Prev:    &pb.Hash32{V: alState.Head.GetV()},
		Seq:     alState.Seq + 1,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:     &pb.AccountId{V: boPub},
			Amount: amount,
			Fee:    fee,
			// ReceivableId may be set after txid derivation, but is NOT part of signing bytes for SEND.
		}},
	}
	signTx(send, alPriv)

	// Derive txid + expected receivable_id (for display; validators compute)
	txid, _ := crypto.TxID(send)
	rid := crypto.ReceivableIDFromTxID(txid)
	// Client MAY set it (validators require match). Optional:
	send.GetSend().ReceivableId = &pb.Hash32{V: rid[:]}

	mustSubmit(baseURL, send)

	fmt.Println("Sent txid:", hex.EncodeToString(txid[:]))
	fmt.Println("Receivable:", hex.EncodeToString(rid[:]))

	// Poll until Bob sees the receivable (meaning SEND committed at epoch close)
	targetRID := waitForReceivable(baseURL, boPub, rid[:], pollEvery, maxWait)
	fmt.Println("Bob receivable id:", hex.EncodeToString(targetRID))

	// Fetch Bob state
	boState := mustGetAccount(baseURL, boPub)

	recv := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: boPub},
		Prev:    &pb.Hash32{V: boState.Head.GetV()},
		Seq:     boState.Seq + 1,
		Body: &pb.Tx_Receive{Receive: &pb.TxBodyReceive{
			ReceivableId: &pb.Hash32{V: targetRID},
		}},
	}
	signTx(recv, boPriv)
	mustSubmit(baseURL, recv)

	// Wait until Bob seq increments (RECEIVE committed)
	waitForSeqAtLeast(baseURL, boPub, boState.Seq+1, pollEvery, maxWait)

	// Print final states
	_ = mustGetAccount(baseURL, alPub)
	_ = mustGetAccount(baseURL, boPub)
	fmt.Println("Done.")
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
	var buf bytes.Buffer
	if _, err := protodelim.MarshalTo(&buf, req); err != nil {
		return err
	}

	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(buf.Bytes()))
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

	br := bufio.NewReader(bytes.NewReader(body))
	return protodelim.UnmarshalFrom(br, resp)
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
