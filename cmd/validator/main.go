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

	arbHex := strings.TrimSpace(os.Getenv("GENESIS_ARBITRATOR_HEX"))
	if arbHex == "" {
		log.Fatal("GENESIS_ARBITRATOR_HEX is required (32-byte hex ed25519 public key)")
	}
	arbBytes, err := hex.DecodeString(arbHex)
	if err != nil || len(arbBytes) != 32 {
		log.Fatal("GENESIS_ARBITRATOR_HEX must decode to exactly 32 bytes")
	}
	var genesisArbKey [32]byte
	copy(genesisArbKey[:], arbBytes)
	fmt.Println("Genesis Arbitrator Key:", hex.EncodeToString(genesisArbKey[:]))

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
		CandidatesSkew:            800 * time.Millisecond,
		FundAccount:               fundAcct,
		GenesisAccount:            genesisAcct,
		GenesisSupply:             genSupply,
		GenesisArbitratorPubkey:   genesisArbKey,
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
		_ = writeProtoDelim(w, &pb.Pub32{V: selfID[:]})
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
		if err := readProtoDelim(r.Body, &cl); err != nil {
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
		if err := readProtoDelim(r.Body, &fin); err != nil {
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
		log.Printf("INV CALLED")

		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var inv pb.TxInv
		if err := readProtoDelim(r.Body, &inv); err != nil {
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

		log.Printf("[net] rx /peer/tx/inv from=%x epoch=%d inv=%d want=%d", fromID[:4], inv.Epoch, len(inv.Txid), len(want.Txid))
		_ = writeProtoDelim(w, want)
	})

	mux.HandleFunc("/peer/tx/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var push pb.TxPush
		if err := readProtoDelim(r.Body, &push); err != nil {
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

		log.Printf("[net] rx /peer/tx/push from=%x epoch=%d txs=%d", fromID[:4], push.Epoch, len(push.Tx))
		w.WriteHeader(200)
	})

	mux.HandleFunc("/peer/tx/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var want pb.TxWant
		if err := readProtoDelim(r.Body, &want); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		log.Printf("[net] rx /peer/tx/get epoch=%d want=%d", want.Epoch, len(want.Txid))
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

		log.Printf("[net] ok /peer/tx/get epoch=%d push=%d", out.Epoch, len(out.Tx))
		_ = writeProtoDelim(w, out)
	})

	mux.HandleFunc("/sync/latest", func(w http.ResponseWriter, r *http.Request) {
		latest := engine.LatestFinalizedEpoch()
		_ = writeProtoDelim(w, &pb.SyncLatestResponse{LatestEpoch: latest})
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
		_ = writeProtoDelim(w, resp)
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
		_ = writeProtoDelim(w, resp)
	})

	mux.HandleFunc("/sync/chain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SyncChainRequest
		if err := readProtoDelim(r.Body, &req); err != nil {
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
		_ = writeProtoDelim(w, resp)
	})

	// ---- Public API endpoints (protobuf) ----

	// POST /submit : SubmitTxRequest -> SubmitTxResponse
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SubmitTxRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
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

		// For Logging
		txid, _ := crypto.TxID(req.Tx)

		acct4 := "--------"
		if req.Tx.Account != nil && len(req.Tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", req.Tx.Account.V[:4])
		}

		log.Printf(
			"[api] rx /submit txid=%x acct=%s seq=%d type=%s",
			txid[:4],
			acct4,
			req.Tx.Seq,
			req.Tx.Type.String(),
		)

		resp := &pb.SubmitTxResponse{Ok: false}
		if err := engine.SubmitTx(raw); err != nil {
			resp.Error = &pb.ApiError{Code: 400, Message: "reject", Detail: err.Error()}
			log.Printf("[api] reject /submit txid=%x err=%s", txid[:4], err.Error())
			_ = writeProtoRaw(w, resp)
			return
		}

		resp.Txid = &pb.Hash32{V: txid[:]}
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// POST /account : GetAccountRequest -> GetAccountResponse
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.GetAccountRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			log.Printf("BAD PROTO /account")
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
			_ = writeProtoRaw(w, resp)
			return
		}

		resp.State = &pb.AccountState{
			Account: &pb.AccountId{V: req.Account.V},
			Head:    &pb.Hash32{V: head[:]},
			Balance: bal,
			Seq:     seq,
		}
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// POST /receivables : ListReceivablesRequest -> ListReceivablesResponse
	mux.HandleFunc("/receivables", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("RECEIVABLES")

		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.ListReceivablesRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
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
			_ = writeProtoRaw(w, resp)
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
		_ = writeProtoRaw(w, resp)
	})

	// POST /arbitrator/submit — submit a TX_TYPE_ADD_ARBITRATOR or TX_TYPE_REMOVE_ARBITRATOR
	mux.HandleFunc("/arbitrator/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req pb.SubmitTxRequest
		if err := readProtoRaw(r.Body, &req); err != nil {
			http.Error(w, "bad proto", 400)
			return
		}
		if req.Tx == nil {
			http.Error(w, "missing tx", 400)
			return
		}
		if req.Tx.Type != pb.TxType_TX_TYPE_ADD_ARBITRATOR && req.Tx.Type != pb.TxType_TX_TYPE_REMOVE_ARBITRATOR {
			http.Error(w, "type must be ADD_ARBITRATOR or REMOVE_ARBITRATOR", 400)
			return
		}
		raw, err := core.CanonicalTxBytes(req.Tx)
		if err != nil {
			http.Error(w, "bad tx", 400)
			return
		}
		txid, _ := crypto.TxID(req.Tx)
		log.Printf("[api] rx /arbitrator/submit txid=%x type=%s", txid[:4], req.Tx.Type.String())
		resp := &pb.SubmitTxResponse{Ok: false}
		if err := engine.SubmitTx(raw); err != nil {
			resp.Error = &pb.ApiError{Code: 400, Message: "reject", Detail: err.Error()}
			_ = writeProtoRaw(w, resp)
			return
		}
		resp.Txid = &pb.Hash32{V: txid[:]}
		resp.Ok = true
		_ = writeProtoRaw(w, resp)
	})

	// GET /arbitrator/signer-set — returns current signer set as JSON
	mux.HandleFunc("/arbitrator/signer-set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		ss, err := engine.GetSignerSetState()
		if err != nil {
			http.Error(w, "not found: "+err.Error(), 404)
			return
		}
		head, seq, _ := engine.ArbChainState()
		type out struct {
			ArbChainHead string   `json:"arb_chain_head"`
			ArbChainSeq  uint64   `json:"arb_chain_seq"`
			Pubkeys      []string `json:"pubkeys"`
			Threshold    uint32   `json:"threshold"`
		}
		resp := out{
			ArbChainHead: hex.EncodeToString(head[:]),
			ArbChainSeq:  seq,
			Threshold:    ss.Threshold,
		}
		for _, p := range ss.Pubkeys {
			if p != nil {
				resp.Pubkeys = append(resp.Pubkeys, hex.EncodeToString(p.V))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
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

// ---------------- Proto helpers ----------------
// Public API: RAW protobuf (no length prefix)
// Peer API:  DELIMITED protobuf (varint length prefix)

func writeProtoRaw(w http.ResponseWriter, msg proto.Message) error {
	w.Header().Set("Content-Type", "application/x-protobuf")
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readProtoRaw(r io.Reader, msg proto.Message) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, msg)
}

func writeProtoDelim(w http.ResponseWriter, msg proto.Message) error {
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

func readProtoDelim(r io.Reader, msg proto.Message) error {
	return protodelim.UnmarshalFrom(bufio.NewReader(r), msg)
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
