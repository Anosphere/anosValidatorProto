package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"
)

type accountHeadRow struct {
	Account string `json:"account"`
	Head    string `json:"head"`
	Balance uint64 `json:"balance"`
	Seq     uint64 `json:"seq"`
}

func main() {
	baseURL := "http://127.0.0.1:8080"

	url := baseURL + "/debug/accounts/heads"

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

func printTable(rows []accountHeadRow) {
	fmt.Println()
	fmt.Println("ACCOUNTS")
	fmt.Println("========")

	fmt.Printf(
		"%-66s %-66s %12s %6s\n",
		"ACCOUNT",
		"HEAD",
		"BALANCE",
		"SEQ",
	)
	fmt.Println(stringsRepeat("-", 66+1+66+1+12+1+6))

	for _, r := range rows {
		acct := shortenHex(r.Account, 32)
		head := shortenHex(r.Head, 32)

		fmt.Printf(
			"%-66s %-66s %12d %6d\n",
			acct,
			head,
			r.Balance,
			r.Seq,
		)
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
