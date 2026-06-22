package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type accountHeadRow struct {
	Account string `json:"account"`
	Head    string `json:"head"`
	Balance uint64 `json:"balance"`
	Seq     uint64 `json:"seq"`
	Class   string `json:"class"`

	// Transfer-chain metadata (present only for TRANSFER accounts).
	TransferSource string `json:"transfer_source"`
	TransferDest   string `json:"transfer_destination"`
	TransferUnlock uint64 `json:"transfer_unlock_epoch"`
}

func main() {
	validatorUrlList := splitCSV(getenv("VALIDATOR_URL_LIST", ""))

	log.Print(validatorUrlList[0])

	for _, v := range validatorUrlList {
		getAccountHeads(v)
	}
}

func getAccountHeads(baseUrl string) {
	url := baseUrl + "/debug/accounts/heads"

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("bad status: %s", resp.Status)
	}

	var rows []accountHeadRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		log.Fatalf("decode failed: %v", err)
	}

	if len(rows) == 0 {
		fmt.Println("No accounts found.")
		return
	}

	// Sort by account for stable output (hex string compare)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Account < rows[j].Account
	})

	printTable(rows)
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

func printTable(rows []accountHeadRow) {
	fmt.Println()
	fmt.Println("ACCOUNTS")
	fmt.Println("========")

	fmt.Printf(
		"%-66s %-66s %12s %6s %8s\n",
		"ACCOUNT",
		"HEAD",
		"BALANCE",
		"SEQ",
		"CLASS",
	)
	fmt.Println(stringsRepeat("-", 66+1+66+1+12+1+6+1+8))

	for _, r := range rows {
		acct := shortenHex(r.Account, 32)
		head := shortenHex(r.Head, 32)

		fmt.Printf(
			"%-66s %-66s %12d %6d %8s\n",
			acct,
			head,
			r.Balance,
			r.Seq,
			r.Class,
		)

		// For transfer chains, print an indented detail line with the immutable
		// source/destination/unlock_epoch so the list shows the transfer's parameters.
		if r.Class == "ACCOUNT_CLASS_TRANSFER" {
			fmt.Printf("      ↳ transfer: source=%s  dest=%s  unlock_epoch=%d\n",
				shortenHex(r.TransferSource, 8),
				shortenHex(r.TransferDest, 8),
				r.TransferUnlock,
			)
		}
	}

	fmt.Println()
}

// shortenHex prints full hex if short, otherwise keeps prefix/suffix.
func shortenHex(h string, bytes int) string {
	_, err := hex.DecodeString(h)
	if err != nil || len(h) <= bytes*2 {
		return h
	}
	return h[:8] + "…" + h[len(h)-8:]
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
