// sim-timelocked-transfer demonstrates the TIMELOCKED + TRANSFER-chain lifecycle end to end:
//
//   1. genesis (SPENDING) funds a fresh user U, who receives as TIMELOCKED.
//   2. U moves funds out by sending to a fresh transfer chain T; because U is TIMELOCKED,
//      the receivable is stamped required_dest_class = TRANSFER (source-side restriction).
//   3. T opens itself as a TRANSFER chain (first RECEIVE) with destination D and an
//      unlock epoch = creation_epoch + TIMELOCKED_DELAY_EPOCHS.
//   4. Releasing T -> D BEFORE unlock does not finalize (the chain stays undrained); once
//      the unlock epoch is reached, the release finalizes and D receives.
//   5. A second transfer chain T2 is created and RETURNED to its source U before unlock,
//      showing return-to-source is allowed at any time.
//
// Two negative checks are included: claiming the timelocked-funded receivable as a
// SPENDING account does not finalize, and release-before-unlock does not finalize.
//
// Env: VALIDATOR_URL_LIST, GENESIS_HEX, GENESIS_PRIVATE_KEY, GENESIS_UNIX_MS, EPOCH_MS,
// TIMELOCKED_DELAY_EPOCHS.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"anos/internal/core"
	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	urls := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	if len(urls) == 0 {
		log.Fatal("VALIDATOR_URL_LIST is required")
	}
	baseURL := urls[0]

	genPriv := ed25519.PrivateKey(mustHex(getenv("GENESIS_PRIVATE_KEY", "")))
	genPub := mustHex(getenv("GENESIS_HEX", ""))

	genesisMs := getenvInt64("GENESIS_UNIX_MS", 0)
	epochMs := getenvInt64("EPOCH_MS", 5000)
	delay := getenvUint64("TIMELOCKED_DELAY_EPOCHS", 120960)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required")
	}
	log.Printf("epoch params: genesisMs=%d epochMs=%d delay=%d (current epoch=%d)",
		genesisMs, epochMs, delay, currentEpoch(genesisMs, epochMs))

	// Fresh participants.
	uPub, uPriv := newKeypair()   // the TIMELOCKED user
	dPub, dPriv := newKeypair()   // release destination (a normal SPENDING account)
	t1Pub, t1Priv := newKeypair() // transfer chain #1 (release-after-unlock demo)
	t2Pub, t2Priv := newKeypair() // transfer chain #2 (return-to-source demo)

	log.Printf("U  (timelocked) = %x", uPub)
	log.Printf("D  (destination)= %x", dPub)
	log.Printf("T1 (transfer)   = %x", t1Pub)
	log.Printf("T2 (transfer)   = %x", t2Pub)

	const fundAmount = uint64(1000) * core.UnitsPerAnos // 1000 Anos to U
	const moveAmount = uint64(100) * core.UnitsPerAnos  // 100 Anos per transfer

	// 1) genesis -> U, U receives as TIMELOCKED
	banner("STEP 1: fund U and establish it as TIMELOCKED")
	ridU := doSend(baseURL, genPub, genPriv, pb.AccountClass_ACCOUNT_CLASS_SPENDING, uPub, fundAmount)
	doReceive(baseURL, uPub, uPriv, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, ridU, nil, 0)
	uSt := mustAccount(baseURL, uPub)
	assert(uSt.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, "U should be TIMELOCKED")
	assert(uSt.Balance == fundAmount, "U should hold the funded amount")
	log.Printf("OK: U is TIMELOCKED with %d units", uSt.Balance)

	// 2) U -> T1 (creates a transfer-restricted receivable)
	banner("STEP 2: U sends to transfer chain T1 (source-side restriction -> TRANSFER)")
	ridT1 := doSend(baseURL, uPub, uPriv, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, t1Pub, moveAmount)

	// Negative check: the timelocked-funded receivable must NOT be claimable as SPENDING.
	banner("NEGATIVE CHECK: claiming T1's receivable as SPENDING must not finalize")
	badRecv := buildReceive(t1Pub, t1Priv, pb.AccountClass_ACCOUNT_CLASS_SPENDING, ridT1, nil, 0, mustAccount(baseURL, t1Pub))
	trySubmit(baseURL, badRecv)
	if waitSeqOrTimeout(baseURL, t1Pub, 1, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: SPENDING claim of a transfer-restricted receivable finalized (should be rejected)")
	}
	log.Printf("OK: SPENDING claim did not finalize (source-side restriction enforced)")

	// 3) T1 opens as TRANSFER with unlock = now + delay (+margin)
	banner("STEP 3: open T1 as a TRANSFER chain")
	unlock1 := currentEpoch(genesisMs, epochMs) + delay + 3 // margin for finalization lag
	log.Printf("T1 unlock epoch = %d (current %d + delay %d + margin 3)", unlock1, currentEpoch(genesisMs, epochMs), delay)
	doReceive(baseURL, t1Pub, t1Priv, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, ridT1, dPub, unlock1)
	t1St := mustAccount(baseURL, t1Pub)
	assert(t1St.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "T1 should be TRANSFER")
	assert(t1St.Balance == moveAmount, "T1 should hold the moved amount")
	log.Printf("OK: T1 is a TRANSFER chain holding %d units, unlock epoch %d", t1St.Balance, unlock1)

	// 4a) release T1 -> D BEFORE unlock: must not finalize
	banner("STEP 4a: release T1 -> D BEFORE unlock must be rejected")
	releaseTx := buildSend(t1Pub, t1Priv, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, dPub, t1St.Balance, 0, mustAccount(baseURL, t1Pub))
	trySubmit(baseURL, releaseTx)
	if waitSeqOrTimeout(baseURL, t1Pub, 2, 4, genesisMs, epochMs) {
		log.Fatal("FAIL: release-before-unlock finalized (timelock not enforced)")
	}
	log.Printf("OK: release-before-unlock did not finalize (epoch=%d < unlock=%d)",
		currentEpoch(genesisMs, epochMs), unlock1)

	// 4b) wait for unlock, then release
	banner("STEP 4b: wait for unlock, then release T1 -> D")
	waitUntilEpoch(unlock1+1, genesisMs, epochMs)
	log.Printf("reached epoch %d >= unlock %d; submitting release", currentEpoch(genesisMs, epochMs), unlock1)
	releaseTx = buildSend(t1Pub, t1Priv, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, dPub, t1St.Balance, 0, mustAccount(baseURL, t1Pub))
	mustSubmit(baseURL, releaseTx)
	waitForSeqAtLeast(baseURL, t1Pub, 2)
	t1St = mustAccount(baseURL, t1Pub)
	assert(t1St.Balance == 0, "T1 should be drained after release")
	log.Printf("OK: T1 released and drained (balance=%d)", t1St.Balance)

	// 4c) D receives the released funds as a normal SPENDING account
	banner("STEP 4c: D receives the released funds")
	relRID := crypto.ReceivableIDFromTxID(mustTxID(releaseTx))
	doReceive(baseURL, dPub, dPriv, pb.AccountClass_ACCOUNT_CLASS_SPENDING, relRID[:], nil, 0)
	dSt := mustAccount(baseURL, dPub)
	assert(dSt.Balance == moveAmount, "D should have received the released amount")
	log.Printf("OK: D received %d units (class=%s)", dSt.Balance, dSt.AccountClass)

	// 5) return-to-source: U -> T2 -> back to U before unlock
	banner("STEP 5: return-to-source demo (T2 -> U before unlock)")
	ridT2 := doSend(baseURL, uPub, uPriv, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, t2Pub, moveAmount)
	unlock2 := currentEpoch(genesisMs, epochMs) + delay + 3
	doReceive(baseURL, t2Pub, t2Priv, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, ridT2, dPub, unlock2)
	t2St := mustAccount(baseURL, t2Pub)
	assert(t2St.AccountClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER, "T2 should be TRANSFER")
	log.Printf("OK: T2 created (unlock %d); returning to source U BEFORE unlock", unlock2)

	returnTx := buildSend(t2Pub, t2Priv, pb.AccountClass_ACCOUNT_CLASS_TRANSFER, uPub, t2St.Balance, 0, mustAccount(baseURL, t2Pub))
	mustSubmit(baseURL, returnTx)
	waitForSeqAtLeast(baseURL, t2Pub, 2)
	t2St = mustAccount(baseURL, t2Pub)
	assert(t2St.Balance == 0, "T2 should be drained after return")
	log.Printf("OK: T2 returned to source and drained while still locked (epoch=%d < unlock=%d)",
		currentEpoch(genesisMs, epochMs), unlock2)

	// U receives the returned funds (stays TIMELOCKED)
	retRID := crypto.ReceivableIDFromTxID(mustTxID(returnTx))
	doReceive(baseURL, uPub, uPriv, pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED, retRID[:], nil, 0)
	uSt = mustAccount(baseURL, uPub)
	log.Printf("OK: U received the returned funds; U balance now %d units (class=%s)", uSt.Balance, uSt.AccountClass)

	banner("ALL CHECKS PASSED")
	log.Printf("Final: U bal=%d class=%s | D bal=%d class=%s",
		uSt.Balance, uSt.AccountClass, dSt.Balance, dSt.AccountClass)
}

// ---------------------------------------------------------------------------------------
// Tx builders + flow helpers
// ---------------------------------------------------------------------------------------

// doSend builds, signs, submits a normal SEND and waits for the sender's seq to advance.
// Returns the recipient receivable id.
func doSend(baseURL string, fromPub []byte, fromPriv ed25519.PrivateKey, fromClass pb.AccountClass, toPub []byte, amount uint64) []byte {
	st := mustAccount(baseURL, fromPub)
	tx := buildSend(fromPub, fromPriv, fromClass, toPub, amount, core.ExpectedFee(amount), st)
	mustSubmit(baseURL, tx)
	waitForSeqAtLeast(baseURL, fromPub, st.Seq+1)
	rid := crypto.ReceivableIDFromTxID(mustTxID(tx))
	return rid[:]
}

// doReceive builds, signs, submits a RECEIVE and waits for the receiver's seq to advance.
func doReceive(baseURL string, acctPub []byte, acctPriv ed25519.PrivateKey, class pb.AccountClass, rid []byte, transferDest []byte, unlock uint64) {
	st := mustAccount(baseURL, acctPub)
	tx := buildReceive(acctPub, acctPriv, class, rid, transferDest, unlock, st)
	mustSubmit(baseURL, tx)
	waitForSeqAtLeast(baseURL, acctPub, st.Seq+1)
}

func buildSend(fromPub []byte, fromPriv ed25519.PrivateKey, fromClass pb.AccountClass, toPub []byte, amount, fee uint64, st *pb.AccountState) *pb.Tx {
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_SEND,
		Account: &pb.AccountId{V: fromPub},
		Prev:    &pb.Hash32{V: st.Head.GetV()},
		Seq:     st.Seq + 1,
		Body: &pb.Tx_Send{Send: &pb.TxBodySend{
			To:           &pb.AccountId{V: toPub},
			Amount:       amount,
			Fee:          fee,
			AccountClass: fromClass,
		}},
	}
	signTx(tx, fromPriv)
	rid := crypto.ReceivableIDFromTxID(mustTxID(tx))
	tx.GetSend().ReceivableId = &pb.Hash32{V: rid[:]}
	return tx
}

func buildReceive(acctPub []byte, acctPriv ed25519.PrivateKey, class pb.AccountClass, rid []byte, transferDest []byte, unlock uint64, st *pb.AccountState) *pb.Tx {
	body := &pb.TxBodyReceive{
		ReceivableId: &pb.Hash32{V: rid},
		AccountClass: class,
	}
	if class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
		body.TransferDestination = &pb.AccountId{V: transferDest}
		body.TransferUnlockEpoch = unlock
	}
	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_RECEIVE,
		Account: &pb.AccountId{V: acctPub},
		Prev:    &pb.Hash32{V: st.Head.GetV()},
		Seq:     st.Seq + 1,
		Body:    &pb.Tx_Receive{Receive: body},
	}
	signTx(tx, acctPriv)
	return tx
}

// ---------------------------------------------------------------------------------------
// Epoch helpers (computed exactly like the validator: epoch = (now-genesis)/epochMs + 1)
// ---------------------------------------------------------------------------------------

func currentEpoch(genesisMs, epochMs int64) uint64 {
	now := time.Now().UnixMilli()
	if now < genesisMs {
		return 1
	}
	return uint64((now-genesisMs)/epochMs) + 1
}

func waitUntilEpoch(target uint64, genesisMs, epochMs int64) {
	for currentEpoch(genesisMs, epochMs) < target {
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
}

// waitSeqOrTimeout returns true if acct reaches wantSeq within `epochs` epochs, else false.
func waitSeqOrTimeout(baseURL string, acct []byte, wantSeq, epochs uint64, genesisMs, epochMs int64) bool {
	deadline := currentEpoch(genesisMs, epochMs) + epochs
	for currentEpoch(genesisMs, epochMs) <= deadline {
		if mustAccount(baseURL, acct).Seq >= wantSeq {
			return true
		}
		time.Sleep(time.Duration(epochMs) * time.Millisecond / 2)
	}
	return mustAccount(baseURL, acct).Seq >= wantSeq
}

func waitForSeqAtLeast(baseURL string, acct []byte, wantSeq uint64) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		if mustAccount(baseURL, acct).Seq >= wantSeq {
			return
		}
		if time.Now().After(deadline) {
			log.Fatalf("timed out waiting for acct=%x seq>=%d", acct[:4], wantSeq)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------------------
// HTTP + crypto plumbing
// ---------------------------------------------------------------------------------------

func signTx(tx *pb.Tx, priv ed25519.PrivateKey) {
	h, _, err := crypto.MsgHash(tx)
	if err != nil {
		log.Fatal(err)
	}
	tx.Sig = &pb.Sig64{V: ed25519.Sign(priv, h[:])}
}

func mustTxID(tx *pb.Tx) [32]byte {
	id, err := crypto.TxID(tx)
	if err != nil {
		log.Fatal(err)
	}
	return id
}

func mustSubmit(baseURL string, tx *pb.Tx) {
	if ok, detail := trySubmit(baseURL, tx); !ok {
		log.Fatalf("submit rejected: %s", detail)
	}
}

func trySubmit(baseURL string, tx *pb.Tx) (bool, string) {
	req := &pb.SubmitTxRequest{Tx: tx}
	resp := &pb.SubmitTxResponse{}
	if err := postProto(baseURL+"/submit", req, resp); err != nil {
		return false, err.Error()
	}
	if !resp.Ok {
		if resp.Error != nil {
			return false, resp.Error.Detail
		}
		return false, "rejected"
	}
	return true, ""
}

func mustAccount(baseURL string, acct []byte) *pb.AccountState {
	req := &pb.GetAccountRequest{Account: &pb.AccountId{V: acct}}
	resp := &pb.GetAccountResponse{}
	if err := postProto(baseURL+"/account", req, resp); err != nil {
		log.Fatal(err)
	}
	if !resp.Ok || resp.State == nil {
		// fresh account: treat as zero state
		return &pb.AccountState{Account: &pb.AccountId{V: acct}, Head: &pb.Hash32{V: make([]byte, 32)}}
	}
	return resp.State
}

func postProto(url string, req, resp proto.Message) error {
	b, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(b))
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

// ---------------------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------------------

func newKeypair() ([]byte, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return pub, priv
}

func assert(cond bool, msg string) {
	if !cond {
		log.Fatalf("ASSERT FAILED: %s", msg)
	}
}

func banner(s string) {
	log.Printf("──────────────────────────────────────────────────────────")
	log.Printf("  %s", s)
	log.Printf("──────────────────────────────────────────────────────────")
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		log.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
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

func getenvInt64(k string, def int64) int64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getenvUint64(k string, def uint64) uint64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
