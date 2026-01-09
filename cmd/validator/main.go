package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/core"
	"anos/internal/crypto"
	pb "anos/internal/proto"
)

func main() {
	port := getenv("PORT", "8080")
	dbPath := getenv("DB_PATH", "validator.db")
	peers := splitCSV(getenv("PEERS", "")) // comma-separated base URLs

	epochMS, _ := strconv.Atoi(getenv("EPOCH_MS", "5000"))
	if epochMS <= 0 {
		epochMS = 5000
	}

	seedHex := strings.TrimSpace(os.Getenv("VALIDATOR_SEED_HEX"))
	if seedHex == "" {
		log.Fatal("VALIDATOR_SEED_HEX is required (32-byte hex)")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("VALIDATOR_SEED_HEX is required (32-byte hex)")
	}

	pub, priv := crypto.ValidatorKeypairFromSeed(seed)

	fundHex := strings.TrimSpace(os.Getenv("FUND_ACCOUNT_HEX"))
	if fundHex == "" {
		log.Fatal("FUND_ACCOUNT_HEX is required (32-byte hex public key)")
	}
	fundBytes, err := hex.DecodeString(fundHex)
	if err != nil || len(fundBytes) != 32 {
		log.Fatal("FUND_ACCOUNT_HEX must decode to exactly 32 bytes")
	}
	var fundAcct [32]byte
	copy(fundAcct[:], fundBytes)

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	engine, err := core.NewEngine(core.EngineConfig{
		DB:            db,
		ValidatorPriv: priv,
		ValidatorPub:  pub,
		Peers:         peers,
		EpochDuration: time.Duration(epochMS) * time.Millisecond,
		QuorumPercent: 80,
		FundAccount:   fundAcct,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	engine.Start(ctx)

	mux := http.NewServeMux()

	// POST /faucet?acct=<hex32>&amount=<u64> (dev/admin)
	mux.HandleFunc("/faucet", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		acctHex := r.URL.Query().Get("acct")
		amountStr := r.URL.Query().Get("amount")
		acctBytes, err := hex.DecodeString(strings.TrimSpace(acctHex))
		if err != nil || len(acctBytes) != 32 {
			http.Error(w, "need ?acct=<hex32>", 400)
			return
		}
		amt, err := strconv.ParseUint(strings.TrimSpace(amountStr), 10, 64)
		if err != nil {
			http.Error(w, "need ?amount=<u64>", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], acctBytes)
		if err := engine.Faucet(acct, amt); err != nil {
			http.Error(w, "error", 500)
			return
		}
		w.WriteHeader(200)
	})

	// ---- Peer endpoints (protobuf-delimited streams) ----

	// GET /peer/id -> Pub32
	mux.HandleFunc("/peer/id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_ = writeProto(w, &pb.Pub32{V: pub})
	})

	// POST /peer/candidates
	// Body is a protobuf-delimited stream (protodelim):
	//   1) Pub32  (validator_id)
	//   2) EpochRecord (epoch, optional state_root carries sender's list_hash)
	//   3) Sig64  (signature over candidates list hash)
	//   4) Tx ... (0..N full transactions)
	mux.HandleFunc("/peer/candidates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		br := bufio.NewReader(r.Body)

		var vid pb.Pub32
		if err := protodelim.UnmarshalFrom(br, &vid); err != nil {
			http.Error(w, "bad proto (validator_id)", 400)
			return
		}
		if len(vid.V) != 32 {
			http.Error(w, "bad validator_id length", 400)
			return
		}

		var er pb.EpochRecord
		if err := protodelim.UnmarshalFrom(br, &er); err != nil {
			http.Error(w, "bad proto (epoch)", 400)
			return
		}

		var sig pb.Sig64
		if err := protodelim.UnmarshalFrom(br, &sig); err != nil {
			http.Error(w, "bad proto (sig)", 400)
			return
		}
		if len(sig.V) != 64 {
			http.Error(w, "bad sig length", 400)
			return
		}

		// Read remaining Tx messages
		var raws [][]byte
		var txids [][32]byte
		for {
			var tx pb.Tx
			err := protodelim.UnmarshalFrom(br, &tx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				http.Error(w, "bad proto (tx stream)", 400)
				return
			}

			// Marshal each tx back to bytes for Engine CandidateList.Txs
			raw, err := proto.Marshal(&tx)
			if err != nil {
				continue
			}
			id, err := crypto.TxID(&tx)
			if err != nil {
				continue
			}

			raws = append(raws, raw)
			txids = append(txids, id)
		}

		listHash := crypto.CandidatesListHash(txids)

		var vid32 [32]byte
		copy(vid32[:], vid.V)
		var lh32 [32]byte
		copy(lh32[:], listHash[:])
		var sig64 [64]byte
		copy(sig64[:], sig.V)

		// Optional cross-check against sender-provided list hash (carried in EpochRecord.state_root)
		if er.StateRoot != nil && len(er.StateRoot.V) == 32 {
			if !bytesEq(er.StateRoot.V, listHash[:]) {
				http.Error(w, "reject: list_hash mismatch", 400)
				return
			}
		}

		cl := &core.CandidateList{
			Epoch:       er.Epoch,
			ValidatorID: vid32,
			ListHash:    lh32,
			Sig:         sig64,
			Txs:         raws,
		}

		from := r.Header.Get("X-Validator-URL")
		if from == "" {
			// For local dev this is fine. For production, prefer X-Validator-URL.
			from = r.RemoteAddr
		}

		if err := engine.ReceiveCandidateList(from, cl); err != nil {
			http.Error(w, "reject: "+err.Error(), 400)
			return
		}
		w.WriteHeader(200)
	})

	// ---- Public API endpoints (protobuf) ----

	// POST /submit : SubmitTxRequest -> SubmitTxResponse
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SubmitTxRequest
		if err := readProto(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Tx == nil {
			http.Error(w, "missing tx", 400)
			return
		}
		raw, err := proto.Marshal(req.Tx)
		if err != nil {
			http.Error(w, "bad tx", 400)
			return
		}

		resp := &pb.SubmitTxResponse{Ok: false}
		if err := engine.SubmitTx(raw); err != nil {
			resp.Error = &pb.ApiError{Code: 400, Message: "reject", Detail: err.Error()}
			writeProtoResponse(w, resp)
			return
		}

		txid, err := crypto.TxID(req.Tx)
		if err == nil {
			resp.Txid = &pb.Hash32{V: txid[:]}
		}
		resp.Ok = true
		writeProtoResponse(w, resp)
	})

	// POST /account : GetAccountRequest -> GetAccountResponse
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.GetAccountRequest
		if err := readProto(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 {
			http.Error(w, "bad account", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)

		head, bal, seq, err := engine.AccountState(acct)
		resp := &pb.GetAccountResponse{Ok: false}
		if err != nil {
			resp.Error = &pb.ApiError{Code: 500, Message: "error", Detail: err.Error()}
			writeProtoResponse(w, resp)
			return
		}

		resp.State = &pb.AccountState{
			Account: &pb.AccountId{V: req.Account.V},
			Head:    &pb.Hash32{V: head[:]},
			Balance: bal,
			Seq:     seq,
		}
		resp.Ok = true
		writeProtoResponse(w, resp)
	})

	// POST /receivables : ListReceivablesRequest -> ListReceivablesResponse
	mux.HandleFunc("/receivables", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.ListReceivablesRequest
		if err := readProto(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 {
			http.Error(w, "bad account", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)

		recs, err := engine.ListReceivables(acct)
		resp := &pb.ListReceivablesResponse{Ok: false}
		if err != nil {
			resp.Error = &pb.ApiError{Code: 500, Message: "error", Detail: err.Error()}
			writeProtoResponse(w, resp)
			return
		}

		// include_claimed default false
		if !req.IncludeClaimed {
			filtered := make([]*pb.Receivable, 0, len(recs))
			for _, rr := range recs {
				if rr != nil && !rr.Claimed {
					filtered = append(filtered, rr)
				}
			}
			recs = filtered
		}

		resp.Receivables = recs
		resp.Ok = true
		writeProtoResponse(w, resp)
	})

	srv := &http.Server{Addr: ":" + port, Handler: mux}

	log.Printf("validator listening on :%s (peers=%d, epoch=%dms)", port, len(peers), epochMS)

	go func() {
		_ = srv.ListenAndServe()
	}()

	// Shutdown on signal
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	cancel()

	_ = srv.Shutdown(context.Background())
}

func writeProtoResponse(w http.ResponseWriter, msg proto.Message) {
	w.Header().Set("Content-Type", "application/x-protobuf")
	_ = writeProto(w, msg)
}

func writeProto(w io.Writer, msg proto.Message) error {
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readProto(r io.Reader, msg proto.Message) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, msg)
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
