package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	epochMS, _ := strconv.Atoi(getenv("EPOCH_MS", "5000"))
	if epochMS <= 0 {
		epochMS = 5000
	}

	genesisMs, _ := strconv.ParseInt(getenv("GENESIS_UNIX_MS", "0"), 10, 64)
	if genesisMs == 0 {
		log.Fatal("GENESIS_UNIX_MS is required (milliseconds since unix epoch); must be identical on all validators")
	}

	kmsKey := strings.TrimSpace(os.Getenv("KMS_KEY_NAME"))

	var signer core.ValidatorSigner
	var selfID [33]byte

	if kmsKey != "" {
		kmsSigner, err := core.NewKMSSigner(ctx, kmsKey)
		if err != nil {
			log.Fatal(err)
		}
		defer kmsSigner.Close()
		signer = kmsSigner
		selfID = kmsSigner.PublicKeyCompressed()
	} else {
		privHex := strings.TrimSpace(os.Getenv("VALIDATOR_ECDSA_PRIV"))
		if privHex == "" {
			log.Fatal("VALIDATOR_ECDSA_PRIV is required (32-byte hex scalar D) when KMS_KEY_NAME is not set")
		}
		privECDSA, err := crypto.LoadP256PrivateKeyFromHex(privHex)
		if err != nil {
			log.Fatalf("VALIDATOR_ECDSA_PRIV invalid: %v", err)
		}
		selfID = crypto.CompressP256PublicKey(&privECDSA.PublicKey)
		signer = core.NewLocalP256Signer(privECDSA)
	}

	fmt.Println("Validator Public Key:", hex.EncodeToString(selfID[:]))

	setCSV := strings.TrimSpace(os.Getenv("VALIDATOR_SET_PUBKEYS"))
	if setCSV == "" {
		log.Fatal("VALIDATOR_SET_PUBKEYS is required (csv of 33-byte compressed pubkeys hex)")
	}
	validatorSet, err := crypto.ParseValidatorSetCSV(setCSV)
	if err != nil {
		log.Fatalf("VALIDATOR_SET_PUBKEYS invalid: %v", err)
	}
	if _, ok := validatorSet[selfID]; !ok {
		log.Fatal("validator set does not include this validator's public key")
	}

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

	genHex := strings.TrimSpace(os.Getenv("GENESIS_HEX"))
	if genHex == "" {
		log.Fatal("GENESIS_HEX is required (32-byte hex public key)")
	}
	genBytes, err := hex.DecodeString(genHex)
	if err != nil || len(genBytes) != 32 {
		log.Fatal("GENESIS_HEX must decode to exactly 32 bytes")
	}
	var genesisAcct [32]byte
	copy(genesisAcct[:], genBytes)

	genSupplyStr := strings.TrimSpace(os.Getenv("GENESIS_SUPPLY_UNITS"))
	if genSupplyStr == "" {
		log.Fatal("GENESIS_SUPPLY_UNITS is required (uint64)")
	}
	genSupply, err := strconv.ParseUint(genSupplyStr, 10, 64)
	if err != nil {
		log.Fatal("GENESIS_SUPPLY_UNITS must be uint64")
	}

	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	engine, err := core.NewEngine(core.EngineConfig{
		DB:                        db,
		Signer:                    signer,
		ValidatorSet:              validatorSet,
		Peers:                     peers,
		GenesisUnixMs:             genesisMs,
		EpochDuration:             time.Duration(epochMS) * time.Millisecond,
		QuorumPercent:             80,
		FinalizationQuorumPercent: 60,
		FinalizationSkew:          800 * time.Millisecond,
		FundAccount:               fundAcct,
		GenesisAccount:            genesisAcct,
		GenesisSupply:             genSupply,
	})

	if err != nil {
		log.Fatal(err)
	}

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
		_ = writeProto(w, &pb.Pub32{V: selfID[:]})
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
		var cl pb.CandidateListV2
		if err := readProto(r.Body, &cl); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if cl.Proposer == nil || len(cl.Proposer.V) != 33 {
			http.Error(w, "bad proposer", 400)
			return
		}
		if cl.ListHash == nil || len(cl.ListHash.V) != 32 {
			http.Error(w, "bad list_hash", 400)
			return
		}
		if cl.Sig == nil || len(cl.Sig.V) < 64 || len(cl.Sig.V) > 80 {
			http.Error(w, "bad sig", 400)
			return
		}

		var vid [33]byte
		copy(vid[:], cl.Proposer.V)
		var lh [32]byte
		copy(lh[:], cl.ListHash.V)

		txids := make([][32]byte, 0, len(cl.Txid))
		for _, h := range cl.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var id [32]byte
			copy(id[:], h.V)
			txids = append(txids, id)
		}

		c := &core.CandidateList{
			Epoch:       cl.Epoch,
			ValidatorID: vid,
			ListHash:    lh,
			SigDER:      append([]byte(nil), cl.Sig.V...),
			TxIDs:       txids,
		}

		from := r.Header.Get("X-Validator-URL")
		if from == "" {
			from = r.RemoteAddr
		}
		if err := engine.ReceiveCandidateList(from, c); err != nil {
			http.Error(w, "reject: "+err.Error(), 400)
			return
		}
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/finalization", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var fin pb.EpochFinalization
		if err := readProto(r.Body, &fin); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if fin.Signer == nil || len(fin.Signer.V) != 33 {
			http.Error(w, "bad signer", 400)
			return
		}
		if fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 {
			http.Error(w, "bad accepted hash", 400)
			return
		}
		if fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 {
			http.Error(w, "bad frontiers root", 400)
			return
		}
		if fin.Sig == nil || len(fin.Sig.V) < 64 || len(fin.Sig.V) > 80 {
			http.Error(w, "bad sig", 400)
			return
		}

		if err := engine.ReceiveFinalization(&fin); err != nil {
			http.Error(w, "reject: "+err.Error(), 400)
			return
		}
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/tx/inv", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var inv pb.TxInv
		if err := readProto(r.Body, &inv); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if inv.From == nil || len(inv.From.V) != 33 {
			http.Error(w, "bad from", 400)
			return
		}
		var fromID [33]byte
		copy(fromID[:], inv.From.V)

		// membership check (same as candidates)
		if engine.ValidatorPub(fromID) == nil {
			http.Error(w, "unknown validator", 400)
			return
		}

		want := &pb.TxWant{
			Epoch: inv.Epoch,
			From:  &pb.Pub32{V: inv.From.V},
		}

		for _, h := range inv.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var txid [32]byte
			copy(txid[:], h.V)
			if !engine.HasTx(txid) {
				want.Txid = append(want.Txid, &pb.Hash32{V: h.V})
			}
		}

		writeProto(w, want)
	})

	mux.HandleFunc("/peer/tx/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var push pb.TxPush
		if err := readProto(r.Body, &push); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if push.From == nil || len(push.From.V) != 33 {
			http.Error(w, "bad from", 400)
			return
		}
		var fromID [33]byte
		copy(fromID[:], push.From.V)
		if engine.ValidatorPub(fromID) == nil {
			http.Error(w, "unknown validator", 400)
			return
		}

		for _, tx := range push.Tx {
			if tx == nil {
				continue
			}
			raw, err := core.CanonicalTxBytes(tx)
			if err != nil {
				continue
			}
			_ = engine.ReceiveGossipedTx(raw)
		}
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/tx/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var want pb.TxWant
		if err := readProto(r.Body, &want); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		out := &pb.TxPush{
			Epoch: want.Epoch,
			From:  &pb.Pub32{V: selfID[:]},
		}

		for _, h := range want.Txid {
			if h == nil || len(h.V) != 32 {
				continue
			}
			var txid [32]byte
			copy(txid[:], h.V)
			raw := engine.GetTxBytes(txid)
			if len(raw) == 0 {
				continue
			}
			tx, err := core.ParseTx(raw)
			if err != nil {
				continue
			}
			out.Tx = append(out.Tx, tx)
		}

		writeProto(w, out)
	})

	mux.HandleFunc("/sync/latest", func(w http.ResponseWriter, r *http.Request) {
		latest := engine.LatestFinalizedEpoch()
		writeProto(w, &pb.SyncLatestResponse{LatestEpoch: latest})
	})

	mux.HandleFunc("/sync/finalization", func(w http.ResponseWriter, r *http.Request) {
		epStr := r.URL.Query().Get("epoch")
		ep, err := strconv.ParseUint(strings.TrimSpace(epStr), 10, 64)
		if err != nil {
			http.Error(w, "need ?epoch=<u64>", 400)
			return
		}
		fins, err := core.GetFinalizations(db, ep)
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			http.Error(w, "db error", 500)
			return
		}
		resp := &pb.SyncFinalizationResponse{}
		for _, raw := range fins {
			var f pb.EpochFinalization
			if err := proto.Unmarshal(raw, &f); err != nil {
				continue
			}
			resp.Finalizations = append(resp.Finalizations, &f)
		}
		writeProto(w, resp)
	})

	mux.HandleFunc("/sync/frontiers", func(w http.ResponseWriter, r *http.Request) {
		epStr := r.URL.Query().Get("epoch")
		ep, err := strconv.ParseUint(strings.TrimSpace(epStr), 10, 64)
		if err != nil {
			http.Error(w, "need ?epoch=<u64>", 400)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 1000
		}
		var cursor [32]byte
		if curHex := r.URL.Query().Get("cursor"); curHex != "" {
			b, err := hex.DecodeString(curHex)
			if err == nil && len(b) == 32 {
				copy(cursor[:], b)
			}
		}

		rows, next, err := core.IterEpochFrontiers(db, ep, cursor, limit)
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			http.Error(w, "db error", 500)
			return
		}

		resp := &pb.SyncFrontiersResponse{Epoch: ep}
		for _, row := range rows {
			resp.Entries = append(resp.Entries, &pb.FrontierEntry{
				Account: &pb.AccountId{V: row.AccountID[:]},
				Head:    &pb.Hash32{V: row.HeadHash[:]},
			})
		}
		if next != nil {
			resp.NextCursor = &pb.AccountId{V: next[:]}
		}
		writeProto(w, resp)
	})

	mux.HandleFunc("/sync/chain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SyncChainRequest
		if err := readProto(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Account == nil || len(req.Account.V) != 32 || req.TargetHead == nil || len(req.TargetHead.V) != 32 {
			http.Error(w, "bad request", 400)
			return
		}
		var acct [32]byte
		copy(acct[:], req.Account.V)
		var head [32]byte
		copy(head[:], req.TargetHead.V)

		var have [32]byte
		if req.Have != nil && len(req.Have.V) == 32 {
			copy(have[:], req.Have.V)
		}

		txs, reached := engine.SyncChain(acct, head, have, int(req.MaxBlocks))
		resp := &pb.SyncChainResponse{ReachedHave: reached}
		for _, raw := range txs {
			tx, err := core.ParseTx(raw)
			if err != nil {
				http.Error(w, "bad tx", http.StatusInternalServerError)
				return
			}
			resp.Tx = append(resp.Tx, tx)
		}
		writeProto(w, resp)
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
		raw, err := core.CanonicalTxBytes(req.Tx)
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

	// ---- Debug/DB endpoints (JSON) ----

	// GET /debug/accounts/heads
	// Returns all account heads currently stored in bbolt.
	mux.HandleFunc("/debug/accounts/heads", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}

		rows, err := core.ListAllAccountHeads(db)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), 500)
			return
		}

		type rowJSON struct {
			Account string `json:"account"`
			Head    string `json:"head"`
			Balance uint64 `json:"balance"`
			Seq     uint64 `json:"seq"`
		}

		out := make([]rowJSON, 0, len(rows))
		for _, rr := range rows {
			out = append(out, rowJSON{
				Account: hex.EncodeToString(rr.Account[:]),
				Head:    hex.EncodeToString(rr.Head[:]),
				Balance: rr.Balance,
				Seq:     rr.Seq,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
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

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(shutdownCtx)

}

func writeProtoResponse(w http.ResponseWriter, msg proto.Message) {
	w.Header().Set("Content-Type", "application/x-protobuf")
	_ = writeProto(w, msg)
}

func writeProto(w http.ResponseWriter, msg proto.Message) error {
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

func readProto(r io.Reader, msg proto.Message) error {
	br := bufio.NewReader(r)
	return protodelim.UnmarshalFrom(br, msg)
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
