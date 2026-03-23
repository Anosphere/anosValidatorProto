package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	// Validator URL
	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	if len(validatorUrlList) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is empty")
		os.Exit(1)
	}
	baseURL := validatorUrlList[0]

	newArbHex := getenv("NEW_ARB_HEX", "")
	if newArbHex == "" {
		panic("NEW_ARB_HEX is required (32-byte hex ed25519 pubkey to add)")
	}
	newArbBytes, err := hex.DecodeString(newArbHex)
	if err != nil || len(newArbBytes) != 32 {
		panic("NEW_ARB_HEX must decode to exactly 32 bytes")
	}

	privKeysCSV := getenv("ARB_PRIV_KEYS", "")
	if privKeysCSV == "" {
		panic("ARB_PRIV_KEYS is required (csv of 64-byte hex ed25519 private keys of all current arbitrators)")
	}
	privKeys := parsePrivKeys(privKeysCSV)

	// Fetch current arb chain state from the validator.
	chainState := mustGetSignerSet(baseURL)
	fmt.Printf("arb_chain_head=%s\n", chainState.ArbChainHead)
	fmt.Printf("arb_chain_seq=%d\n", chainState.ArbChainSeq)
	fmt.Printf("current arbitrators (%d):\n", len(chainState.Pubkeys))
	for _, p := range chainState.Pubkeys {
		fmt.Printf("  %s\n", p)
	}

	headBytes, err := hex.DecodeString(chainState.ArbChainHead)
	if err != nil || len(headBytes) != 32 {
		panic("bad arb_chain_head from server")
	}
	var head [32]byte
	copy(head[:], headBytes)

	arbChainID := sha256.Sum256([]byte("ANOS_ARB_CHAIN_V1"))

	tx := &pb.Tx{
		Type:    pb.TxType_TX_TYPE_ADD_ARBITRATOR,
		Account: &pb.AccountId{V: arbChainID[:]},
		Prev:    &pb.Hash32{V: head[:]},
		Seq:     chainState.ArbChainSeq + 1,
		Body: &pb.Tx_AddArbitrator{AddArbitrator: &pb.TxBodyAddArbitrator{
			Pubkey: &pb.Pub32{V: newArbBytes},
		}},
	}

	msgHash, _, err := crypto.MsgHash(tx)
	if err != nil {
		panic(err)
	}

	ms := &pb.MultiSig{}
	for _, priv := range privKeys {
		pub := priv.Public().(ed25519.PublicKey)
		sig := ed25519.Sign(priv, msgHash[:])
		ms.Pubkeys = append(ms.Pubkeys, &pb.Pub32{V: pub})
		ms.Sigs = append(ms.Sigs, &pb.Sig64{V: sig})
	}
	tx.MultiSig = ms

	txid, err := crypto.TxID(tx)
	if err != nil {
		panic(err)
	}
	fmt.Println("txid:", hex.EncodeToString(txid[:]))

	req := &pb.SubmitTxRequest{Tx: tx}
	resp := &pb.SubmitTxResponse{}
	if err := postProto(baseURL+"/arbitrator/submit", req, resp); err != nil {
		panic(err)
	}
	if !resp.Ok {
		panic(fmt.Sprintf("submit rejected: %v", resp.Error))
	}
	fmt.Println("submitted ok")
}

type signerSetResp struct {
	ArbChainHead string   `json:"arb_chain_head"`
	ArbChainSeq  uint64   `json:"arb_chain_seq"`
	Pubkeys      []string `json:"pubkeys"`
	Threshold    uint32   `json:"threshold"`
}

func mustGetSignerSet(baseURL string) signerSetResp {
	resp, err := http.Get(baseURL + "/arbitrator/signer-set")
	if err != nil {
		panic(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		panic(fmt.Sprintf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	var out signerSetResp
	if err := json.Unmarshal(body, &out); err != nil {
		panic(err)
	}
	return out
}

func parsePrivKeys(csv string) []ed25519.PrivateKey {
	parts := strings.Split(csv, ",")
	out := make([]ed25519.PrivateKey, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 64 {
			panic(fmt.Sprintf("ARB_PRIV_KEYS: each key must be 64-byte hex, got len=%d", len(b)))
		}
		out = append(out, ed25519.PrivateKey(b))
	}
	if len(out) == 0 {
		panic("ARB_PRIV_KEYS: no valid keys found")
	}
	return out
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

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
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
