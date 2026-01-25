package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

type EngineConfig struct {
	DB           *bbolt.DB
	Signer       ValidatorSigner
	ValidatorSet map[[33]byte]*ecdsa.PublicKey // validator_id -> pubkey (membership)

	Peers         []string
	EpochDuration time.Duration
	// GenesisUnixMs anchors epoch numbering to wall-clock time:
	// epoch = floor((nowMs - genesisMs) / epochMs) + 1
	GenesisUnixMs             int64
	QuorumPercent             int // used only for conflict resolution
	FinalizationQuorumPercent int // quorum for EpochFinalization agreement (default 60)
	HTTPClient                *http.Client
	CandidatesSkew            time.Duration
	FinalizationSkew          time.Duration

	FundAccount [32]byte
}

type Engine struct {
	cfg EngineConfig

	mu      sync.Mutex
	mempool [][]byte
	// epoch -> validator_id -> candidate list
	peerLists     map[uint64]map[[33]byte]*CandidateList
	txPool        map[[32]byte][]byte     // txid -> raw tx bytes (submitted/gossiped/fetched)
	conflictPool  map[[32]byte][][32]byte // keyHash -> txids (all conflict candidates we’ve seen)
	approved      map[[32]byte][32]byte   // keyHash -> txid we “approve” this epoch
	gossipPending map[[32]byte]struct{}   // txids to announce on next gossip tick

	peerFinals map[uint64]map[[33]byte]*pb.EpochFinalization // epoch -> signer -> fin

	startOnce sync.Once
}

type CandidateList struct {
	Epoch       uint64
	ValidatorID [33]byte
	ListHash    [32]byte
	SigDER      []byte
	TxIDs       [][32]byte // txids only (votes)
}

// For consistent logging
func (e *Engine) elog(epoch uint64, format string, args ...any) {
	prefix := append([]any{epoch}, args...)
	log.Printf("[epoch=%d] "+format, prefix...)
}

func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.DB == nil {
		return nil, errors.New("missing db")
	}
	if cfg.Signer == nil {
		return nil, errors.New("missing signer")
	}
	if len(cfg.ValidatorSet) == 0 {
		return nil, errors.New("missing validator set")
	}
	selfID := cfg.Signer.PublicKeyCompressed()
	if _, ok := cfg.ValidatorSet[selfID]; !ok {
		return nil, errors.New("signer public key not present in validator set")
	}
	if cfg.EpochDuration <= 0 {
		cfg.EpochDuration = 5 * time.Second
	}
	if cfg.GenesisUnixMs == 0 {
		return nil, errors.New("missing genesis time: set GENESIS_UNIX_MS (milliseconds since unix epoch)")
	}

	if cfg.QuorumPercent == 0 {
		cfg.QuorumPercent = 80
	}
	if cfg.FinalizationQuorumPercent == 0 {
		cfg.FinalizationQuorumPercent = 60
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 2 * time.Second}
	}
	if cfg.CandidatesSkew == 0 {
		cfg.CandidatesSkew = 300 * time.Millisecond
	}
	if cfg.FinalizationSkew == 0 {
		cfg.FinalizationSkew = 500 * time.Millisecond
	}
	e := &Engine{
		cfg:       cfg,
		mempool:   make([][]byte, 0, 1024),
		peerLists: make(map[uint64]map[[33]byte]*CandidateList),
	}

	if err := cfg.DB.Update(func(tx *bbolt.Tx) error { return ensureBuckets(tx) }); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Start(ctx context.Context) {
	e.startOnce.Do(func() { go e.loop(ctx) })
}

// SubmitTx enqueues raw tx bytes for this epoch; it only checks signature and basic parse.
func (e *Engine) SubmitTx(raw []byte) error {
	tx, err := ParseTx(raw)
	if err != nil {
		return err
	}
	if err := crypto.VerifyTxSignature(tx); err != nil {
		return err
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return err
	}

	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	e.txPool[txid] = append([]byte(nil), raw...)
	if e.gossipPending == nil {
		e.gossipPending = make(map[[32]byte]struct{})
	}
	e.gossipPending[txid] = struct{}{}
	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}
	if key, ok := conflictKeyHash(tx); ok {
		// store candidate
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)
		// set approval if unset
		if _, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()
	return nil
}

// Faucet credits an account directly (admin/testing).
func (e *Engine) Faucet(acct [32]byte, amount uint64) error {
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		head, bal, seq := getAccount(tx, acct)
		bal += amount
		return putAccount(tx, acct, head, bal, seq)
	})
}

func (e *Engine) AccountState(acct [32]byte) (head [32]byte, bal uint64, seq uint64, err error) {
	err = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		h, b, s := getAccount(tx, acct)
		head, bal, seq = h, b, s
		return nil
	})
	return
}

func (e *Engine) ListReceivables(toAcct [32]byte) ([]*pb.Receivable, error) {
	var out []*pb.Receivable
	err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BRecv)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			_ = k
			var r pb.Receivable
			if err := proto.Unmarshal(v, &r); err != nil {
				return nil
			}
			if r.To != nil && r.To.V != nil && bytesEq32(r.To.V, toAcct) {
				out = append(out, &r)
			}
			return nil
		})
	})
	return out, err
}

// ReceiveCandidateList stores a peer candidate list for an epoch after verifying signature and list hash.
func (e *Engine) ReceiveCandidateList(fromURL string, cl *CandidateList) error {
	_ = fromURL // identity is the pubkey, not URL

	// 1) membership check
	pub := e.cfg.ValidatorSet[cl.ValidatorID]
	if pub == nil {
		return errors.New("unknown validator")
	}

	// 2) canonicalize txids and recompute list hash
	txids := append([][32]byte(nil), cl.TxIDs...)
	sort.Slice(txids, func(i, j int) bool { return bytes.Compare(txids[i][:], txids[j][:]) < 0 })
	recomputed := crypto.CandidatesListHash(txids)
	if recomputed != cl.ListHash {
		return errors.New("reject: list_hash mismatch")
	}

	// 3) verify signature
	digest := crypto.CandidatesDigestP256(cl.Epoch, cl.ValidatorID, cl.ListHash)
	if !crypto.VerifyCandidatesSigP256(pub, digest, cl.SigDER) {
		return errors.New("reject: bad signature")
	}

	// 4) store by (epoch, validator_id)
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.peerLists == nil {
		e.peerLists = make(map[uint64]map[[33]byte]*CandidateList)
	}
	m := e.peerLists[cl.Epoch]
	if m == nil {
		m = make(map[[33]byte]*CandidateList)
		e.peerLists[cl.Epoch] = m
	}

	if prev := m[cl.ValidatorID]; prev != nil {
		// idempotent accept if identical
		if prev.ListHash == cl.ListHash && bytes.Equal(prev.SigDER, cl.SigDER) {
			return nil
		}
		return errors.New("reject: duplicate/conflicting list for validator+epoch")
	}

	m[cl.ValidatorID] = cl
	return nil
}

func (e *Engine) ValidatorPub(id [33]byte) *ecdsa.PublicKey {
	return e.cfg.ValidatorSet[id]
}

func (e *Engine) HasTx(txid [32]byte) bool {
	e.mu.Lock()
	_, ok := e.txPool[txid]
	e.mu.Unlock()
	if ok {
		return true
	}
	found := false
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		found = hasTx(tx, txid)
		return nil
	})
	return found
}

func (e *Engine) GetTxBytes(txid [32]byte) []byte {
	e.mu.Lock()
	if raw, ok := e.txPool[txid]; ok && len(raw) > 0 {
		out := append([]byte(nil), raw...)
		e.mu.Unlock()
		return out
	}
	e.mu.Unlock()

	var out []byte
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		raw, err := getTxRaw(tx, txid)
		if err != nil {
			return nil
		}
		out = raw
		return nil
	})
	return out
}

func (e *Engine) LatestFinalizedEpoch() uint64 {
	var latest uint64
	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BFinalizations)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) < 8 {
				continue
			}
			ep := binary.BigEndian.Uint64(k[:8])
			if ep > latest {
				latest = ep
			}
		}
		return nil
	})
	return latest
}

func (e *Engine) ReceiveGossipedTx(raw []byte) error {
	tx, err := ParseTx(raw)
	if err != nil {
		return err
	}
	// basic signature check now; full snapshot validation happens at epoch close
	if err := crypto.VerifyTxSignature(tx); err != nil {
		return err
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return err
	}

	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	if _, ok := e.txPool[txid]; !ok {
		e.txPool[txid] = append([]byte(nil), raw...)
	}
	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}
	if key, ok := conflictKeyHash(tx); ok {
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)
		if _, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()
	return nil
}

func (e *Engine) ReceiveFinalization(fin *pb.EpochFinalization) error {
	if fin == nil {
		return errors.New("nil finalization")
	}
	if fin.Signer == nil || len(fin.Signer.V) != 33 {
		return errors.New("bad signer")
	}
	if fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 {
		return errors.New("bad accepted_txids_hash")
	}
	if fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 {
		return errors.New("bad frontiers_root")
	}
	if fin.Sig == nil || len(fin.Sig.V) < 64 || len(fin.Sig.V) > 80 {
		return errors.New("bad sig")
	}

	var signerID [33]byte
	copy(signerID[:], fin.Signer.V)

	pub := e.cfg.ValidatorSet[signerID]
	if pub == nil {
		return errors.New("unknown validator")
	}

	var accepted [32]byte
	copy(accepted[:], fin.AcceptedTxidsHash.V)
	var root [32]byte
	copy(root[:], fin.FrontiersRoot.V)

	digest := crypto.FinalizationDigestP256(fin.Epoch, accepted, root)
	if !crypto.VerifyFinalizationSigP256(pub, digest, fin.Sig.V) {
		return errors.New("bad signature")
	}

	// store raw proto in DB
	raw, err := proto.Marshal(fin)
	if err != nil {
		return err
	}
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		return PutFinalization(tx, fin.Epoch, signerID, raw)
	}); err != nil {
		return err
	}

	// store in memory for quick quorum checks
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peerFinals == nil {
		e.peerFinals = make(map[uint64]map[[33]byte]*pb.EpochFinalization)
	}
	m := e.peerFinals[fin.Epoch]
	if m == nil {
		m = make(map[[33]byte]*pb.EpochFinalization)
		e.peerFinals[fin.Epoch] = m
	}
	// idempotent accept if identical
	if prev := m[signerID]; prev != nil {
		// if same hashes and sig, ignore
		if bytes.Equal(prev.AcceptedTxidsHash.V, fin.AcceptedTxidsHash.V) &&
			bytes.Equal(prev.FrontiersRoot.V, fin.FrontiersRoot.V) &&
			bytes.Equal(prev.Sig.V, fin.Sig.V) {
			return nil
		}
		// conflicting finalization from same signer for same epoch is a protocol violation
		return errors.New("conflicting finalization for signer+epoch")
	}

	m[signerID] = fin
	return nil
}

// SyncChain returns raw tx bytes walking backwards from targetHead (inclusive).
// Stops if it reaches `have` (if non-zero) or hits max blocks or missing tx bytes.
// Returns (txsHeadBackwards, reachedHave).
func (e *Engine) SyncChain(accountID [32]byte, targetHead [32]byte, have [32]byte, max int) ([][]byte, bool) {
	if max <= 0 {
		max = 2000
	}

	var out [][]byte
	reachedHave := false

	_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}

		cur := targetHead
		for i := 0; i < max; i++ {
			// stop if we hit have (and have != zero)
			if have != ([32]byte{}) && bytes.Equal(cur[:], have[:]) {
				reachedHave = true
				break
			}

			raw, err := getTxRaw(tx, cur)
			if err != nil {
				break
			}
			out = append(out, raw)

			ptx, err := ParseTx(raw)
			if err != nil {
				break
			}

			// Your Tx uses Prev (not PrevHash)
			if ptx.Prev == nil || len(ptx.Prev.V) != 32 {
				break
			}
			var prev [32]byte
			copy(prev[:], ptx.Prev.V)

			// stop at zero prev (open/genesis boundary)
			var z [32]byte
			if bytes.Equal(prev[:], z[:]) {
				break
			}

			cur = prev
		}
		return nil
	})

	return out, reachedHave
}

// loop runs epochs.
func (e *Engine) loop(ctx context.Context) {
	epochMs := e.cfg.EpochDuration.Milliseconds()
	if epochMs <= 0 {
		epochMs = 5000
	}

	genesisMs := e.cfg.GenesisUnixMs

	for {
		// If genesis is in the future, wait until it begins.
		nowMs := time.Now().UnixMilli()
		if nowMs < genesisMs {
			wait := time.Duration(genesisMs-nowMs) * time.Millisecond
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}

		// Determine the current wall-clock epoch window.
		epoch := uint64((nowMs-genesisMs)/epochMs) + 1
		epochEndMs := genesisMs + int64(epoch)*epochMs

		start := time.Now()
		e.elog(epoch, " ----- Starting New Epoch ----- ")

		// Snapshot at the *start* of the epoch window (best-effort).
		epochSnap, _ := e.buildSnapshot()

		// Sleep until the epoch boundary (end of this epoch).
		sleepMs := epochEndMs - nowMs
		if sleepMs > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(sleepMs) * time.Millisecond):
			}
		} else {
			// We're already past the boundary (GC pause / scheduling / etc). Continue immediately.
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		// Close: build our candidate list from txs received during this epoch window.
		localRaw := e.drainMempool()
		selfList, _ := e.buildCandidateList(epoch, localRaw, epochSnap)

		e.elog(epoch, "local candidates built (mempool=%d)", len(localRaw))

		// Broadcast once at epoch close
		e.broadcastCandidates(epoch, selfList)

		e.elog(epoch, "broadcast candidates to %d peers", len(e.cfg.Peers))

		// Wait a small skew for peers to arrive
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.cfg.CandidatesSkew):
		}

		peerLists := e.getPeerLists(epoch)

		e.elog(epoch, "peer lists received=%d", len(peerLists))

		// --- Presence quorum gate (liveness) ---
		// "All validators" here means: self + everyone in our configured Peers list.
		// If fewer than 60% are present this epoch, we skip applying anything and retry next epoch.
		expected := 1 + len(e.cfg.Peers)     // self + peers we expect
		present := 1 + len(peerLists)        // self + peers we actually received candidate lists from
		required := (expected*60 + 99) / 100 // ceil(expected * 0.60)
		if required < 1 {
			required = 1
		}

		if present < required {
			log.Printf("epoch %d skipped: presence %d/%d (<60%%); will retry next epoch", epoch, present, expected)

			// Keep local txs so our candidate list can be rebuilt next epoch.
			e.requeueMempool(localRaw)

			epoch++
			continue
		}
		// --- end presence quorum gate ---

		// Model B: Merge union of all valid txs; vote only within conflicts.
		totalValidators := len(e.cfg.ValidatorSet)
		threshold := (totalValidators*e.cfg.QuorumPercent + 99) / 100 // ceil
		if threshold < 1 {
			threshold = 1
		}

		// Union: txid support count (how many lists contained it)
		support := make(map[[32]byte]int)

		// Collect union txids (unique)
		unionSet := make(map[[32]byte]struct{})

		// self votes
		for _, id := range selfList.TxIDs {
			support[id]++
			unionSet[id] = struct{}{}
		}

		// peers votes
		for _, cl := range peerLists {
			for _, id := range cl.TxIDs {
				support[id]++
				unionSet[id] = struct{}{}
			}
		}

		// Resolve unionSet -> slice
		unionIDs := make([][32]byte, 0, len(unionSet))
		for id := range unionSet {
			unionIDs = append(unionIDs, id)
		}

		// Fill txBytesByID from local pool/DB; fetch missing from peers if needed
		txBytesByID := make(map[[32]byte][]byte, len(unionIDs))

		missing := make([][32]byte, 0)
		for _, id := range unionIDs {
			raw := e.GetTxBytes(id) // <- must check txPool then DB
			if len(raw) == 0 {
				missing = append(missing, id)
				continue
			}
			txBytesByID[id] = raw
		}

		// If missing, fetch from peers via /peer/tx/get and try again
		if len(missing) > 0 {
			e.fetchMissingTxs(epoch, missing)
			for _, id := range missing {
				if _, ok := txBytesByID[id]; ok {
					continue
				}
				raw := e.GetTxBytes(id)
				if len(raw) > 0 {
					txBytesByID[id] = raw
				}
			}
		}

		// Validate all txs against snapshot (objective validity)
		validIDs := make([][32]byte, 0, len(txBytesByID))
		validParsed := make(map[[32]byte]*pb.Tx, len(txBytesByID))
		for id, raw := range txBytesByID {
			tx, err := ParseTx(raw)
			if err != nil {
				continue
			}
			// validate returns computed txid; require it matches map key
			cid, err := ValidateTxAgainstSnapshot(tx, epochSnap)
			if err != nil || cid != id {
				continue
			}
			validIDs = append(validIDs, id)
			validParsed[id] = tx
		}

		// Group by conflict key: (account, prev, seq). With snapshot rules, prev/seq are same per account.
		type ckey struct {
			acct [32]byte
			prev [32]byte
			seq  uint64
		}
		conf := make(map[ckey][][32]byte)
		for _, id := range validIDs {
			tx := validParsed[id]
			var acct [32]byte
			copy(acct[:], tx.Account.V)
			var prev [32]byte
			if tx.Prev != nil && len(tx.Prev.V) == 32 {
				copy(prev[:], tx.Prev.V)
			}
			k := ckey{acct: acct, prev: prev, seq: tx.Seq}
			conf[k] = append(conf[k], id)
		}

		// Decide winners
		winners := make(map[[32]byte][32]byte) // acct -> txid
		for k, ids := range conf {
			if len(ids) == 1 {
				winners[k.acct] = ids[0]
				continue
			}
			// conflict: vote only within this group
			// collect candidates reaching threshold
			type cand struct {
				id      [32]byte
				support int
			}
			cands := make([]cand, 0, len(ids))
			for _, id := range ids {
				cands = append(cands, cand{id: id, support: support[id]})
			}
			// Filter by threshold
			eligible := make([]cand, 0, len(cands))
			for _, c := range cands {
				if c.support >= threshold {
					eligible = append(eligible, c)
				}
			}
			if len(eligible) == 0 {
				// safety-first: accept none
				continue
			}
			// pick highest support, tie-break lowest txid
			sort.Slice(eligible, func(i, j int) bool {
				if eligible[i].support != eligible[j].support {
					return eligible[i].support > eligible[j].support
				}
				return bytes.Compare(eligible[i].id[:], eligible[j].id[:]) < 0
			})
			winners[k.acct] = eligible[0].id
		}

		e.elog(epoch, "apply begin (winner_accounts=%d, candidate_txs=%d)", len(winners), len(validParsed))
		// --- Finalization (checkpoint anchor) ---
		acceptedIDs := make([][32]byte, 0, len(winners))
		for _, txid := range winners {
			acceptedIDs = append(acceptedIDs, txid)
		}
		sort.Slice(acceptedIDs, func(i, j int) bool { return bytes.Compare(acceptedIDs[i][:], acceptedIDs[j][:]) < 0 })

		acceptedHash := crypto.CandidatesListHash(acceptedIDs)

		// snapshot epoch frontiers after commit, then compute root
		if err := SaveEpochFrontiers(e.cfg.DB, epoch); err != nil {
			e.elog(epoch, "finalization: SaveEpochFrontiers error: %v", err)
		} else {
			root, err := ComputeFrontiersRoot(e.cfg.DB, epoch)
			if err != nil {
				e.elog(epoch, "finalization: ComputeFrontiersRoot error: %v", err)
			} else {
				signerID := e.cfg.Signer.PublicKeyCompressed()
				digest := crypto.FinalizationDigestP256(epoch, acceptedHash, root)
				sigDER, sigErr := e.cfg.Signer.SignDigest(digest)
				if sigErr != nil {
					e.elog(epoch, "finalization: sign error: %v", sigErr)
				} else {
					fin := &pb.EpochFinalization{
						Epoch:             epoch,
						AcceptedTxidsHash: &pb.Hash32{V: acceptedHash[:]},
						FrontiersRoot:     &pb.Hash32{V: root[:]},
						Signer:            &pb.Pub32{V: signerID[:]},
						Sig:               &pb.SigDER{V: sigDER}, // <-- SigDER (not Sig64)
					}

					// store our own finalization (and memory map)
					if err := e.ReceiveFinalization(fin); err != nil {
						e.elog(epoch, "finalization: store self error: %v", err)
					}

					// broadcast to peers
					e.broadcastFinalization(fin)

					// allow some skew to receive peers’ finalizations (peers must finish apply first)
					select {
					case <-ctx.Done():
						return
					case <-time.After(e.cfg.FinalizationSkew):
					}

					// quorum check (log-only for now; later this triggers resync)
					qAccepted, qRoot, qCount, qNeed := e.finalizationQuorum(epoch)
					if qCount >= qNeed {
						if !bytes.Equal(qAccepted[:], acceptedHash[:]) || !bytes.Equal(qRoot[:], root[:]) {
							e.elog(epoch, "FINALIZATION MISMATCH quorum=%d/%d (trigger resync later): have=(%x,%x) want=(%x,%x)",
								qCount, qNeed, acceptedHash[:], root[:], qAccepted[:], qRoot[:])
						} else {
							e.elog(epoch, "finalized epoch %d quorum=%d/%d: (elapsed=%s)", epoch, qCount, qNeed, time.Since(start).Truncate(time.Millisecond))
						}
					} else {
						e.elog(epoch, "finalization not reached: %d/%d", qCount, qNeed)
					}
				}
			}
		}
		// --- end finalization ---
	}
}

func (e *Engine) buildSnapshot() (*Snapshot, error) {
	snap := &Snapshot{
		Accounts:    make(map[[32]byte]AccountSnap),
		Receivables: make(map[[32]byte]struct{}),
	}
	err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		ab := tx.Bucket(BAccounts)
		if ab != nil {
			_ = ab.ForEach(func(k, v []byte) error {
				if len(k) == 32 {
					var acct [32]byte
					copy(acct[:], k)
					h, bal, seq, ok := unpackAccount(v)
					if ok {
						snap.Accounts[acct] = AccountSnap{Head: h, Balance: bal, Seq: seq}
					}
				}
				return nil
			})
		}
		rb := tx.Bucket(BRecv)
		if rb != nil {
			_ = rb.ForEach(func(k, v []byte) error {
				if len(k) == 32 {
					var rid [32]byte
					copy(rid[:], k)
					// only include unclaimed receivables in snapshot set
					var rec pb.Receivable
					if err := proto.Unmarshal(v, &rec); err == nil {
						if !rec.Claimed {
							snap.Receivables[rid] = struct{}{}
						}
					}
				}
				return nil
			})
		}
		return nil
	})
	return snap, err
}

func (e *Engine) drainMempool() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.mempool
	e.mempool = make([][]byte, 0, 1024)
	return out
}

func (e *Engine) requeueMempool(raws [][]byte) {
	if len(raws) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	// Prepend, so txs that were already seen get retried first.
	rebuilt := make([][]byte, 0, len(raws))
	for _, r := range raws {
		rebuilt = append(rebuilt, append([]byte(nil), r...))
	}
	e.mempool = append(rebuilt, e.mempool...)
}

// buildCandidateListV2 builds a txid-only candidate list ("votes").
// It ignores raws and uses e.approved (one tx per conflict key).
func (e *Engine) buildCandidateList(epoch uint64, raws [][]byte, snap *Snapshot) (*CandidateList, [][32]byte) {
	_ = raws
	_ = snap

	e.mu.Lock()
	ids := make([][32]byte, 0, len(e.approved))
	for _, txid := range e.approved {
		ids = append(ids, txid)
	}
	e.mu.Unlock()

	// stable order for list_hash/signature
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })

	listHash := crypto.CandidatesListHash(ids)
	vid := e.cfg.Signer.PublicKeyCompressed()

	digest := crypto.CandidatesDigestP256(epoch, vid, listHash)
	sigDER, err := e.cfg.Signer.SignDigest(digest)
	if err != nil {
		sigDER = nil
	}

	cl := &CandidateList{
		Epoch:       epoch,
		ValidatorID: vid,
		ListHash:    listHash,
		SigDER:      sigDER,
		TxIDs:       ids, // <-- txids only
	}

	return cl, ids
}

func (e *Engine) broadcastCandidates(epoch uint64, cl *CandidateList) {
	msg := &pb.CandidateListV2{
		Epoch:    cl.Epoch,
		Proposer: &pb.Pub32{V: cl.ValidatorID[:]},
		ListHash: &pb.Hash32{V: cl.ListHash[:]},
		Sig:      &pb.SigDER{V: cl.SigDER}, // if your proto uses SigDER; use Sig64 if you kept Sig64
	}
	for _, id := range cl.TxIDs {
		msg.Txid = append(msg.Txid, &pb.Hash32{V: id[:]})
	}

	for _, peer := range e.cfg.Peers {
		peer = strings.TrimRight(peer, "/")
		go func(p string) {
			var buf bytes.Buffer
			_, _ = protodelim.MarshalTo(&buf, msg)

			req, _ := http.NewRequest("POST", p+"/peer/candidates", &buf)
			req.Header.Set("Content-Type", "application/x-protobuf")
			// Optional: include your own URL if you use it for debugging
			// req.Header.Set("X-Validator-URL", e.cfg.SelfURL)

			resp, err := e.cfg.HTTPClient.Do(req)
			if err != nil {
				log.Printf("candidates POST to %s failed: %v", p, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				log.Printf("candidates POST to %s non-2xx: %s body=%q", p, resp.Status, string(b))
			}
		}(peer)
	}

	_ = epoch
}

func (e *Engine) broadcastFinalization(fin *pb.EpochFinalization) {
	if fin == nil {
		return
	}
	for _, peer := range e.cfg.Peers {
		peer = strings.TrimRight(peer, "/")
		go func(p string) {
			var buf bytes.Buffer
			_, _ = protodelim.MarshalTo(&buf, fin)

			req, _ := http.NewRequest("POST", p+"/peer/finalization", &buf)
			req.Header.Set("Content-Type", "application/x-protobuf")
			resp, err := e.cfg.HTTPClient.Do(req)
			if err != nil {
				log.Printf("finalization POST to %s failed: %v", p, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				b, _ := io.ReadAll(resp.Body)
				log.Printf("finalization POST to %s non-2xx: %s body=%q", p, resp.Status, string(b))
			}
		}(peer)
	}
}

func (e *Engine) finalizationQuorum(epoch uint64) (bestAccepted [32]byte, bestRoot [32]byte, count int, need int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	total := len(e.cfg.ValidatorSet)
	need = (total*e.cfg.FinalizationQuorumPercent + 99) / 100
	if need < 1 {
		need = 1
	}

	m := e.peerFinals[epoch]
	if m == nil {
		return [32]byte{}, [32]byte{}, 0, need
	}

	type key struct {
		accepted [32]byte
		root     [32]byte
	}
	counts := make(map[key]int)

	for _, fin := range m {
		if fin == nil || fin.AcceptedTxidsHash == nil || fin.FrontiersRoot == nil {
			continue
		}
		var a [32]byte
		copy(a[:], fin.AcceptedTxidsHash.V)
		var r [32]byte
		copy(r[:], fin.FrontiersRoot.V)
		k := key{accepted: a, root: r}
		counts[k]++
	}

	bestK := key{}
	bestC := 0
	for k, c := range counts {
		if c > bestC {
			bestC = c
			bestK = k
		}
	}

	return bestK.accepted, bestK.root, bestC, need
}

func (e *Engine) getPeerLists(epoch uint64) map[[33]byte]*CandidateList {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[[33]byte]*CandidateList)
	if m, ok := e.peerLists[epoch]; ok {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func (e *Engine) applyWinners(winners map[[32]byte][32]byte, txBytesByID map[[32]byte][]byte, parsed map[[32]byte]*pb.Tx) error {
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		view := &bboltTxView{tx: tx}
		for _, id := range winners {
			raw := txBytesByID[id]
			p := parsed[id]
			if raw == nil || p == nil {
				// parse if missing
				if raw != nil {
					pp, err := ParseTx(raw)
					if err == nil {
						p = pp
					}
				}
			}
			if raw == nil || p == nil {
				continue
			}
			_ = ApplyTx(view, raw, p, id, e.cfg.FundAccount)
		}
		return nil
	})
}

func conflictKeyHash(tx *pb.Tx) ([32]byte, bool) {
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return [32]byte{}, false
	}
	if tx.Prev == nil || len(tx.Prev.V) != 32 {
		return [32]byte{}, false
	}
	seq := tx.Seq

	// hash(account || prev || seqBE)
	buf := make([]byte, 32+32+8)
	copy(buf[:32], tx.Account.V)
	copy(buf[32:64], tx.Prev.V)
	binary.BigEndian.PutUint64(buf[64:], seq)
	return sha256.Sum256(buf), true
}

func appendUnique32(list [][32]byte, v [32]byte) [][32]byte {
	for _, x := range list {
		if bytes.Equal(x[:], v[:]) {
			return list
		}
	}
	return append(list, v)
}

func (e *Engine) fetchMissingTxs(epoch uint64, missing [][32]byte) {
	if len(missing) == 0 {
		return
	}

	for _, peer := range e.cfg.Peers {
		peer = strings.TrimRight(peer, "/")

		vid := e.cfg.Signer.PublicKeyCompressed()
		want := &pb.TxWant{
			Epoch: epoch,
			From:  &pb.Pub32{V: vid[:]},
		}
		for _, id := range missing {
			want.Txid = append(want.Txid, &pb.Hash32{V: id[:]})
		}

		var buf bytes.Buffer
		_, _ = protodelim.MarshalTo(&buf, want)

		req, _ := http.NewRequest("POST", peer+"/peer/tx/get", &buf)
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := e.cfg.HTTPClient.Do(req)
		if err != nil || resp == nil {
			continue
		}

		func() {
			defer resp.Body.Close()

			var push pb.TxPush
			br := bufio.NewReader(resp.Body)
			if err := protodelim.UnmarshalFrom(br, &push); err != nil {
				return
			}

			for _, tx := range push.Tx {
				if tx == nil {
					continue
				}
				raw, err := proto.Marshal(tx)
				if err != nil {
					continue
				}
				_ = e.ReceiveGossipedTx(raw)
			}
		}()

		return
	}
}
