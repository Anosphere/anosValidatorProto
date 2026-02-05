// cmd/simulators/sim-get-user-receivables/main.go
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "anos/internal/proto"
)

func main() {
	userHex := flag.String("userHex", "", "Hex pubkey of account to inspect (64 hex chars). Can also be a .csv path containing one value.")
	includeClaimed := flag.Bool("includeClaimed", false, "Include claimed receivables (default false)")
	flag.Parse()

	if strings.TrimSpace(*userHex) == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --userHex is required")
		os.Exit(1)
	}

	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))
	if len(validatorUrlList) == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: VALIDATOR_URL_LIST is required (e.g. http://localhost:8080)")
		os.Exit(1)
	}
	baseURL := validatorUrlList[0]

	hexStr := strings.TrimSpace(*userHex)
	if strings.HasSuffix(strings.ToLower(hexStr), ".csv") {
		b, err := os.ReadFile(hexStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed reading %s: %v\n", hexStr, err)
			os.Exit(1)
		}
		toks := splitCSV(strings.ReplaceAll(string(b), "\n", ","))
		if len(toks) == 0 {
			fmt.Fprintf(os.Stderr, "ERROR: %s contained no values\n", hexStr)
			os.Exit(1)
		}
		hexStr = toks[0]
	}

	acct, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: bad --userHex %q: %v\n", hexStr, err)
		os.Exit(1)
	}

	// Optional: show basic account info for context
	st := mustGetAccount(baseURL, acct)
	fmt.Printf("Account: %s\n", hex.EncodeToString(acct))
	fmt.Printf("Seq:     %d\n", st.Seq)
	fmt.Printf("Balance: %d units\n", st.Balance)
	fmt.Printf("Head:    %s\n", shortHex(st.GetHead().GetV()))

	// The real receivables list comes from /receivables
	recs := mustListReceivables(baseURL, acct, *includeClaimed)

	fmt.Printf("\nReceivables: %d (includeClaimed=%v)\n", len(recs), *includeClaimed)
	if len(recs) == 0 {
		return
	}

	for i, r := range recs {
		if r == nil {
			fmt.Printf("  [%03d] <nil>\n", i)
			continue
		}
		fmt.Printf("  [%03d] id=%s  from=%s  to=%s  amount=%d  fee=%d  created_by_tx=%s  claimed=%v  claimed_by_tx=%s\n",
			i,
			shortHex(r.GetId().GetV()),
			shortHex(r.GetFrom().GetV()),
			shortHex(r.GetTo().GetV()),
			r.GetAmount(),
			r.GetFee(),
			shortHex(r.GetCreatedByTx().GetV()),
			r.GetClaimed(),
			shortHex(r.GetClaimedByTx().GetV()),
		)
	}
}

// ---------------- endpoint wrappers ----------------

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

func mustListReceivables(baseURL string, acct []byte, includeClaimed bool) []*pb.Receivable {
	req := &pb.ListReceivablesRequest{
		Account:        &pb.AccountId{V: acct},
		IncludeClaimed: includeClaimed,
	}
	resp := &pb.ListReceivablesResponse{}
	if err := postProto(baseURL+"/receivables", req, resp); err != nil {
		panic(err)
	}
	if !resp.Ok {
		panic(fmt.Sprintf("receivables failed: %v", resp.Error))
	}
	return resp.Receivables
}

// ---------------- generic helpers ----------------

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

func shortHex(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	h := hex.EncodeToString(b)
	if len(h) <= 16 {
		return h
	}
	return h[:16]
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
