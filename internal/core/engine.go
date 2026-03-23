package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/bits"
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

	FundAccount    [32]byte
	GenesisAccount [32]byte
	GenesisSupply  uint64

	// GenesisArbitratorPubkey is the ed25519 pubkey (32 bytes) of the initial arbitrator.
	// Set via GENESIS_ARBITRATOR_HEX. Must be identical on all validators.
	GenesisArbitratorPubkey [32]byte
}

type Engine struct {
	cfg EngineConfig

	mu sync.Mutex
	// epoch -> validator_id -> candidate list
	peerLists     map[uint64]map[[33]byte]*CandidateList
	txPool        map[[32]byte][]byte     // txid -> raw tx bytes (submitted/gossiped/fetched)
	txSeenEpoch   map[[32]byte]uint64     // txid -> epoch when first seen
	conflictPool  map[[32]byte][][32]byte // keyHash -> txids (all conflict candidates we’ve seen)
	approved      map[[32]byte][32]byte   // keyHash -> txid we “approve” this epoch
	gossipPending map[[32]byte]struct{}   // txids to announce on next gossip tick
	gossipMask    map[[32]byte]uint64     // txid -> bitmask of peers that have it via push/want(ack)

	peerFinals map[uint64]map[[33]byte]*pb.EpochFinalization // epoch -> signer -> fin

	// --- resync state (minimal state machine) ---
	resync            ResyncState
	resyncNextAttempt time.Time
	resyncFailCount   int

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
		peerLists: make(map[uint64]map[[33]byte]*CandidateList),
	}

	if err := cfg.DB.Update(func(tx *bbolt.Tx) error { return ensureBuckets(tx) }); err != nil {
		return nil, err
	}
	if err := e.ensureGenesisOnBoot(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Engine) Start(ctx context.Context) {
	e.startOnce.Do(func() {
		go e.loop(ctx)
		go e.gossipLoop(ctx)
	})
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

	// If we already have this tx (either still in txPool OR persisted in DB),
	// don't re-enqueue it or re-announce it. This prevents repeated /tx/get cycles.
	if e.HasTx(txid) {
		acct4 := "--------"
		if tx.Account != nil && len(tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
		}
		log.Printf("[tx] submit dup txid=%x acct=%s seq=%d type=%s", txid[:4], acct4, tx.Seq, tx.Type.String())
		return nil
	}

	seen := e.epochNow()

	dup := false

	e.mu.Lock()
	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	if _, ok := e.txPool[txid]; ok {
		dup = true
	} else {
		e.txPool[txid] = append([]byte(nil), raw...)
	}

	if e.txSeenEpoch == nil {
		e.txSeenEpoch = make(map[[32]byte]uint64)
	}
	if _, exists := e.txSeenEpoch[txid]; !exists {
		e.txSeenEpoch[txid] = seen
	}

	if e.gossipPending == nil {
		e.gossipPending = make(map[[32]byte]struct{})
	}
	e.gossipPending[txid] = struct{}{}

	// temp log
	log.Printf("[tx] submit-pool txid=%x epoch=%d wallMs=%d", txid[:4], seen, time.Now().UnixMilli())

	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	if _, ok := e.gossipMask[txid]; !ok {
		e.gossipMask[txid] = 0
	}

	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}

	if key, ok := conflictKeyHash(tx); ok {
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

		// Deterministic approval: lowest txid wins for this conflict key.
		if cur, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		} else if bytes.Compare(txid[:], cur[:]) < 0 {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()

	acct4 := "--------"
	if tx.Account != nil && len(tx.Account.V) >= 4 {
		acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
	}
	status := "ok"
	if dup {
		status = "dup"
	}
	log.Printf("[tx] submit %s txid=%x acct=%s seq=%d type=%s", status, txid[:4], acct4, tx.Seq, tx.Type.String())
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

// GetSignerSetState returns the current arbitrator SignerSet.
func (e *Engine) GetSignerSetState() (*pb.SignerSet, error) {
	return GetSignerSet(e.cfg.DB)
}

// ArbChainState returns the current arbitrator chain head hash and seq number.
func (e *Engine) ArbChainState() (head [32]byte, seq uint64, err error) {
	err = e.cfg.DB.View(func(tx *bbolt.Tx) error {
		head, seq = getArbChain(tx)
		return nil
	})
	return head, seq, err
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
		if tx.Bucket(BTxs) == nil {
			return nil
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

	// If we already have this tx persisted (likely already applied), ignore it.
	// This prevents re-adding completed txs to txPool/approved and triggering fetch loops.
	if e.HasTx(txid) {
		acct4 := "--------"
		if tx.Account != nil && len(tx.Account.V) >= 4 {
			acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
		}
		log.Printf("[tx] gossip dup txid=%x acct=%s seq=%d type=%s", txid[:4], acct4, tx.Seq, tx.Type.String())
		return nil
	}

	seen := e.epochNow()

	e.mu.Lock()
	if e.txSeenEpoch == nil {
		e.txSeenEpoch = make(map[[32]byte]uint64)
	}
	if _, exists := e.txSeenEpoch[txid]; !exists {
		e.txSeenEpoch[txid] = seen
	}

	gdup := false

	if e.txPool == nil {
		e.txPool = make(map[[32]byte][]byte)
	}
	if _, ok := e.txPool[txid]; ok {
		gdup = true
	} else {
		e.txPool[txid] = append([]byte(nil), raw...)
	}
	if e.gossipPending == nil {
		e.gossipPending = make(map[[32]byte]struct{})
	}
	e.gossipPending[txid] = struct{}{}
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	if _, ok := e.gossipMask[txid]; !ok {
		e.gossipMask[txid] = 0
	}
	if e.conflictPool == nil {
		e.conflictPool = make(map[[32]byte][][32]byte)
	}
	if e.approved == nil {
		e.approved = make(map[[32]byte][32]byte)
	}
	if key, ok := conflictKeyHash(tx); ok {
		e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

		// Deterministic approval: lowest txid wins for this conflict key.
		if cur, exists := e.approved[key]; !exists {
			e.approved[key] = txid
		} else if bytes.Compare(txid[:], cur[:]) < 0 {
			e.approved[key] = txid
		}
	}
	e.mu.Unlock()

	acct4 := "--------"
	if tx.Account != nil && len(tx.Account.V) >= 4 {
		acct4 = fmt.Sprintf("%x", tx.Account.V[:4])
	}
	status := "ok"
	if gdup {
		status = "dup"
	}
	log.Printf("[tx] gossip %s txid=%x acct=%s seq=%d type=%s", status, txid[:4], acct4, tx.Seq, tx.Type.String())

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
//
// accountID is used only for diagnostics / special synthetic-anchor handling;
// tx bytes themselves are always read from BTxs.
func (e *Engine) SyncChain(accountID [32]byte, targetHead [32]byte, have [32]byte, max int) ([][]byte, bool) {
	log.Printf("SYNCCHAIN ENGINE CALLED acct=%x target=%x have=%x max=%d", accountID[:4], targetHead[:4], have[:4], max)
	if max <= 0 {
		max = 2000
	}

	var out [][]byte
	reachedHave := false
	arbID := ArbChainID
	arbGenesisHead := sha256.Sum256(append([]byte("ANOS_ARB_CHAIN_GENESIS_V1:"), ArbChainID[:]...))

	if err := e.cfg.DB.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(BTxs) == nil {
			return nil
		}

		cur := targetHead
		for i := 0; i < max; i++ {
			if have != ([32]byte{}) && cur == have {
				reachedHave = true
				break
			}

			raw, err := getTxRaw(tx, cur)
			if err != nil {
				// Missing current head bytes is only acceptable if this exact hash is the requested boundary.
				if have != ([32]byte{}) && cur == have {
					reachedHave = true
				}
				log.Printf("SYNCCHAIN head missing acct=%x cur=%x have=%x reached=%v", accountID[:4], cur[:4], have[:4], reachedHave)
				break
			}

			out = append(out, raw)

			ptx, err := ParseTx(raw)
			if err != nil {
				log.Printf("SYNCCHAIN parse error acct=%x cur=%x: %v", accountID[:4], cur[:4], err)
				break
			}

			if ptx.Prev == nil || len(ptx.Prev.V) != 32 {
				log.Printf("SYNCCHAIN missing prev acct=%x cur=%x", accountID[:4], cur[:4])
				break
			}

			var prev [32]byte
			copy(prev[:], ptx.Prev.V)

			if have != ([32]byte{}) && prev == have {
				reachedHave = true
				break
			}

			if prev == ([32]byte{}) {
				if have == ([32]byte{}) {
					reachedHave = true
				}
				break
			}

			if have == ([32]byte{}) {
				if accountID == arbID {
					// For arb chain, only the deterministic arb genesis head counts as the synthetic base.
					if prev == arbGenesisHead {
						reachedHave = true
						log.Printf("SYNCCHAIN arb reached deterministic genesis prev=%x", prev[:4])
						break
					}

					// Any other missing prev is a real problem, not a synthetic boundary.
					if _, err := getTxRaw(tx, prev); err != nil {
						log.Printf("SYNCCHAIN arb historical gap cur=%x prev=%x target=%x", cur[:4], prev[:4], targetHead[:4])
						reachedHave = false
						break
					}
				} else {
					// Normal account-chain heuristic: missing prev means synthetic base.
					if _, err := getTxRaw(tx, prev); err != nil {
						log.Printf("SYNCCHAIN acct=%x stopping at synthetic base prev=%x", accountID[:4], prev[:4])
						reachedHave = true
						break
					}
				}
			}

			cur = prev
		}
		return nil
	}); err != nil {
		log.Printf("SYNCCHAIN DB.View error: %v", err)
	}

	log.Printf("SYNCCHAIN DONE acct=%x target=%x out=%d reached=%v", accountID[:4], targetHead[:4], len(out), reachedHave)
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
		// If we're in resync mode, short-circuit normal epoch processing.
		// This prevents continuing to apply epochs while we know we're divergent.
		if e.resync.IsActive() {
			// Backoff gate: don't hammer resync in a tight loop on repeated failure.
			e.mu.Lock()
			next := e.resyncNextAttempt
			active := e.resync.IsActive()
			e.mu.Unlock()

			if active && !next.IsZero() && time.Now().Before(next) {
				// Sleep until next attempt (or context cancel).
				d := time.Until(next)
				if d > 250*time.Millisecond {
					d = 250 * time.Millisecond
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
				continue
			}

			_ = e.runResync(ctx)

			// After resync attempt (success or failure), restart loop to re-evaluate wall-clock epoch.
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}

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
		log.Printf("[epoch=%d] phase:epoch-calc wallMs=%d epochEndMs=%d gapMs=%d", epoch, nowMs, epochEndMs, epochEndMs-nowMs)

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
		log.Printf("[epoch=%d] phase:candidates-start wallMs=%d poolSize=%d approvedSize=%d", epoch, time.Now().UnixMilli(), len(e.txPool), len(e.approved))
		selfList, _ := e.buildCandidateList(epoch, epochSnap)
		log.Printf("[epoch=%d] phase:candidates-built txids=%d wallMs=%d", epoch, len(selfList.TxIDs), time.Now().UnixMilli())

		// Broadcast once at epoch close
		e.broadcastCandidates(epoch, selfList)
		log.Printf("[epoch=%d] phase:candidates-broadcast-done wallMs=%d", epoch, time.Now().UnixMilli())

		// Wait a small skew for peers to arrive
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.cfg.CandidatesSkew):
		}

		log.Printf("[epoch=%d] phase:skew-done wallMs=%d", epoch, time.Now().UnixMilli())
		peerLists := e.getPeerLists(epoch)
		for vid, cl := range peerLists {
			log.Printf("[epoch=%d] phase:peer-list-received from=%x txids=%d", epoch, vid[:4], len(cl.TxIDs))
		}
		if len(peerLists) == 0 {
			log.Printf("[epoch=%d] phase:peer-list-received NONE", epoch)
		}

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

		log.Printf("[epoch=%d] phase:union-built unionSize=%d localHave=%d missing=%d", epoch, len(unionIDs), len(txBytesByID), len(missing))

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

		// --- DRY-RUN: compute hashes WITHOUT writing to DB ---
		// Instead of applying winners immediately, we compute what the acceptedHash
		// and frontiersRoot would be, then broadcast finalization and wait for quorum
		// agreement before committing anything. This prevents the need for resync
		// when validators disagree.
		acceptedIDs := make([][32]byte, 0, len(winners))
		for _, txid := range winners {
			acceptedIDs = append(acceptedIDs, txid)
		}
		sort.Slice(acceptedIDs, func(i, j int) bool { return bytes.Compare(acceptedIDs[i][:], acceptedIDs[j][:]) < 0 })

		acceptedHash := crypto.CandidatesListHash(acceptedIDs)

		// Compute what the frontiers root would look like after applying winners,
		// without actually writing to DB.
		dryRunRoot, err := ComputeDryRunFrontiersRoot(e.cfg.DB, winners)
		if err != nil {
			e.elog(epoch, "dry-run frontiers root error: %v — retrying", err)
			continue
		}

		log.Printf("[epoch=%d] phase:dry-run-done winners=%d acceptedHash=%x frontiersRoot=%x wallMs=%d",
			epoch, len(winners), acceptedHash[:4], dryRunRoot[:4], time.Now().UnixMilli())

		// --- Finalization (checkpoint anchor) ---
		// Sign and broadcast our proposed finalization, including the full list of
		// accepted txids so that mismatched validators can apply the quorum's set
		// without needing a full resync.
		signerID := e.cfg.Signer.PublicKeyCompressed()
		digest := crypto.FinalizationDigestP256(epoch, acceptedHash, dryRunRoot)
		sigDER, sigErr := e.cfg.Signer.SignDigest(digest)
		if sigErr != nil {
			e.elog(epoch, "finalization: sign error: %v — retrying", sigErr)
			continue
		}

		// Build accepted txid bytes for the proto field
		acceptedTxidBytes := make([][]byte, len(acceptedIDs))
		for i, id := range acceptedIDs {
			cp := make([]byte, 32)
			copy(cp, id[:])
			acceptedTxidBytes[i] = cp
		}

		fin := &pb.EpochFinalization{
			Epoch:             epoch,
			AcceptedTxidsHash: &pb.Hash32{V: acceptedHash[:]},
			FrontiersRoot:     &pb.Hash32{V: dryRunRoot[:]},
			Signer:            &pb.Pub32{V: signerID[:]},
			Sig:               &pb.SigDER{V: sigDER}, // <-- SigDER (not Sig64)
			AcceptedTxids:     acceptedTxidBytes,
		}

		// store our own finalization (and memory map)
		if err := e.ReceiveFinalization(fin); err != nil {
			e.elog(epoch, "finalization: store self error: %v", err)
		}

		// broadcast to peers
		log.Printf("[epoch=%d] phase:fin-broadcast-start wallMs=%d", epoch, time.Now().UnixMilli())
		e.broadcastFinalization(fin)
		log.Printf("[epoch=%d] phase:fin-broadcast-done wallMs=%d", epoch, time.Now().UnixMilli())

		// allow some skew to receive peers' finalizations (peers must finish apply first)
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.cfg.FinalizationSkew):
		}
		log.Printf("[epoch=%d] phase:fin-skew-done wallMs=%d", epoch, time.Now().UnixMilli())

		// --- Quorum check and commit decision ---
		// Three outcomes:
		// 1) Quorum agrees with us -> commit our winners to DB
		// 2) Quorum agrees on something different -> apply quorum's winner set instead
		// 3) No quorum reached -> discard everything, txs stay in pool for next epoch
		qAccepted, qRoot, qCount, qNeed, qTxids := e.finalizationQuorum(epoch)

		if qCount >= qNeed {
			if bytes.Equal(qAccepted[:], acceptedHash[:]) && bytes.Equal(qRoot[:], dryRunRoot[:]) {
				// MATCH: quorum agrees with us. Commit our winners to DB.
				log.Printf("[epoch=%d] phase:apply-start winners=%d validTxs=%d wallMs=%d", epoch, len(winners), len(validParsed), time.Now().UnixMilli())
				acceptedSet, failedApplied, aerr := e.applyWinners(winners, txBytesByID, validParsed)
				log.Printf("[epoch=%d] phase:apply-done failed=%d wallMs=%d", epoch, len(failedApplied), time.Now().UnixMilli())
				if aerr != nil {
					e.elog(epoch, "apply error: %v — triggering resync", aerr)
					e.triggerResync(epoch, qAccepted, qRoot)
					continue
				}
				if len(failedApplied) > 0 {
					i := 0
					for id, ferr := range failedApplied {
						e.elog(epoch, "apply rejected tx %x...: %v", id[:4], ferr)
						i++
						if i >= 5 {
							break
						}
					}
					e.elog(epoch, "apply had %d failed txs — triggering resync", len(failedApplied))
					e.triggerResync(epoch, qAccepted, qRoot)
					continue
				}

				// snapshot epoch frontiers after commit
				if err := SaveEpochFrontiers(e.cfg.DB, epoch); err != nil {
					e.elog(epoch, "finalization: SaveEpochFrontiers error: %v", err)
				}

				// Cleanup: delete losers + delete accepted-but-failed-apply
				postSnap, _ := e.buildSnapshot()
				log.Printf("[epoch=%d] phase:cleanup-start txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())
				e.cleanupAfterEpoch(epoch, acceptedSet, failedApplied, postSnap)
				log.Printf("[epoch=%d] phase:cleanup-done txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())

				e.elog(epoch,
					"finalized. quorum=%d/%d: (elapsed=%s) : broadcasted to %d : lists received=%d : Applied (winner_accounts=%d, candidate_txs=%d)",
					qCount, qNeed, time.Since(start).Truncate(time.Millisecond), len(e.cfg.Peers), len(peerLists), len(winners), len(validParsed))

			} else {
				// MISMATCH: quorum agreed on something different.
				// Instead of triggering a full resync, try to apply the quorum's winner
				// set directly. The quorum's finalization message includes the actual txid
				// list, so we can fetch any missing tx bytes and apply them.
				e.elog(epoch, "FINALIZATION MISMATCH quorum=%d/%d: have=(%x,%x) want=(%x,%x) — applying quorum set",
					qCount, qNeed, acceptedHash[:4], dryRunRoot[:4], qAccepted[:4], qRoot[:4])

				if len(qTxids) > 0 {
					// Build quorum winners from the txid list
					qWinners := make(map[[32]byte][32]byte)
					qTxBytesMap := make(map[[32]byte][]byte)
					qParsedMap := make(map[[32]byte]*pb.Tx)
					fetchFailed := false

					for _, txid := range qTxids {
						// Try to get tx bytes locally first (from our own pool/DB)
						raw := txBytesByID[txid]
						if len(raw) == 0 {
							raw = e.GetTxBytes(txid)
						}
						if len(raw) == 0 {
							// Fetch from peers
							e.fetchMissingTxs(epoch, [][32]byte{txid})
							raw = e.GetTxBytes(txid)
						}
						if len(raw) == 0 {
							e.elog(epoch, "MISMATCH: cannot find tx bytes for quorum txid %x — triggering resync", txid[:4])
							e.triggerResync(epoch, qAccepted, qRoot)
							fetchFailed = true
							break
						}
						tx, perr := ParseTx(raw)
						if perr != nil {
							e.elog(epoch, "MISMATCH: cannot parse quorum txid %x — triggering resync", txid[:4])
							e.triggerResync(epoch, qAccepted, qRoot)
							fetchFailed = true
							break
						}
						var acct [32]byte
						copy(acct[:], tx.Account.V)
						qWinners[acct] = txid
						qTxBytesMap[txid] = raw
						qParsedMap[txid] = tx
					}

					if !fetchFailed {
						// Apply the quorum's winners instead of our own
						log.Printf("[epoch=%d] phase:apply-quorum-start winners=%d wallMs=%d", epoch, len(qWinners), time.Now().UnixMilli())
						acceptedSet, failedApplied, aerr := e.applyWinners(qWinners, qTxBytesMap, qParsedMap)
						log.Printf("[epoch=%d] phase:apply-quorum-done failed=%d wallMs=%d", epoch, len(failedApplied), time.Now().UnixMilli())
						if aerr != nil || len(failedApplied) > 0 {
							e.elog(epoch, "MISMATCH: apply quorum failed (err=%v, failed=%d) — triggering resync", aerr, len(failedApplied))
							e.triggerResync(epoch, qAccepted, qRoot)
						} else {
							// snapshot epoch frontiers after commit
							if err := SaveEpochFrontiers(e.cfg.DB, epoch); err != nil {
								e.elog(epoch, "finalization: SaveEpochFrontiers error: %v", err)
							}

							// Cleanup: same as normal path
							postSnap, _ := e.buildSnapshot()
							log.Printf("[epoch=%d] phase:cleanup-start txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())
							e.cleanupAfterEpoch(epoch, acceptedSet, failedApplied, postSnap)
							log.Printf("[epoch=%d] phase:cleanup-done txPool=%d wallMs=%d", epoch, len(e.txPool), time.Now().UnixMilli())

							e.elog(epoch, "applied quorum set: %d winners", len(qWinners))
						}
					}
				} else {
					// No txid list available from quorum — must fall back to resync
					e.elog(epoch, "MISMATCH: no quorum txid list available — triggering resync")
					e.triggerResync(epoch, qAccepted, qRoot)
				}
			}
		} else {
			// NO QUORUM: not enough validators responded.
			// Discard everything — no DB writes. Txs stay in pool for next epoch.
			e.elog(epoch, "finalization not reached: %d/%d", qCount, qNeed)
		}
		// --- end finalization ---
	}
}

// gossipLoop periodically advertises pending txids to peers (INV) and, when requested, delivers
// full transactions (PUSH). Gossip is considered "done" for a tx once it has been delivered to a
// majority of our configured peers (not counting self).
//
// This is intentionally memory-only. If a validator restarts or the pool is cleaned before peers
// fetch/push occurs, bytes may be lost; the majority threshold reduces the probability of that.
func (e *Engine) gossipLoop(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.flushGossipOnce(ctx)
		}
	}
}

func (e *Engine) flushGossipOnce(ctx context.Context) {
	if len(e.cfg.Peers) == 0 {
		return
	}

	// Majority of peers (excluding self): floor(n/2)+1
	need := (len(e.cfg.Peers) / 2) + 1
	if need < 1 {
		need = 1
	}

	type peerBatch struct {
		idx int
		url string
		ids [][32]byte
	}

	var batches []peerBatch

	e.mu.Lock()
	if len(e.gossipPending) == 0 {
		e.mu.Unlock()
		return
	}
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}

	// Bound per-tick so protobufs don’t explode.
	const maxTick = 300
	pending := make([][32]byte, 0, minInt(len(e.gossipPending), maxTick))
	for id := range e.gossipPending {
		pending = append(pending, id)
		if len(pending) >= maxTick {
			break
		}
	}

	// Pre-prune txids that already reached majority.
	for _, id := range pending {
		if bits.OnesCount64(e.gossipMask[id]) >= need {
			delete(e.gossipPending, id)
			delete(e.gossipMask, id)
		}
	}

	// Rebuild pending after prune.
	pending = pending[:0]
	for id := range e.gossipPending {
		pending = append(pending, id)
		if len(pending) >= maxTick {
			break
		}
	}

	if len(pending) == 0 {
		e.mu.Unlock()
		return
	}

	// Per-peer selection: only txids not yet acked by that peer.
	for i, peer := range e.cfg.Peers {
		if i >= 63 {
			break // bitmask limitation
		}
		peer = strings.TrimRight(peer, "/")
		bit := uint64(1) << uint(i)

		ids := make([][32]byte, 0, len(pending))
		for _, id := range pending {
			if (e.gossipMask[id] & bit) == 0 {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue
		}
		batches = append(batches, peerBatch{idx: i, url: peer, ids: ids})
	}
	e.mu.Unlock()

	if len(batches) == 0 {
		return
	}

	totalIds := 0
	for _, b := range batches {
		totalIds += len(b.ids)
	}
	log.Printf("[gossip] flushing batches=%d totalIds=%d wallMs=%d", len(batches), totalIds, time.Now().UnixMilli())
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, b := range batches {
		b := b
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			e.gossipToPeer(ctx, b.idx, b.url, b.ids, need)
		}()
	}
	wg.Wait()
}

func (e *Engine) gossipToPeer(ctx context.Context, peerIdx int, peerURL string, ids [][32]byte, need int) {
	if len(ids) == 0 || peerIdx < 0 || peerIdx >= 63 {
		return
	}
	gossipStart := time.Now().UnixMilli()
	log.Printf("[gossip] peer=%s ids=%d start wallMs=%d", peerURL, len(ids), gossipStart)
	bit := uint64(1) << uint(peerIdx)

	epoch := e.epochNow()
	vid := e.cfg.Signer.PublicKeyCompressed()

	inv := &pb.TxInv{Epoch: epoch, From: &pb.Pub32{V: vid[:]}}
	for _, id := range ids {
		inv.Txid = append(inv.Txid, &pb.Hash32{V: id[:]})
	}

	var invBuf bytes.Buffer
	_, _ = protodelim.MarshalTo(&invBuf, inv)

	req, _ := http.NewRequestWithContext(ctx, "POST", peerURL+"/peer/tx/inv", &invBuf)
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil || resp == nil {
		return
	}

	var want pb.TxWant
	func() {
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return
		}
		br := bufio.NewReader(resp.Body)
		_ = protodelim.UnmarshalFrom(br, &want)
	}()

	// If peer wants nothing, treat as ACK for everything we advertised.
	acked := make([][32]byte, 0, len(ids))
	if len(want.Txid) == 0 {
		acked = append(acked, ids...)
		e.recordGossipAck(bit, need, acked)
		return
	}

	// Build PUSH with only wanted txs.
	push := &pb.TxPush{Epoch: epoch, From: &pb.Pub32{V: vid[:]}}
	for _, h := range want.Txid {
		if h == nil || len(h.V) != 32 {
			continue
		}
		var txid [32]byte
		copy(txid[:], h.V)

		raw := e.GetTxBytes(txid)
		if len(raw) == 0 {
			continue
		}
		tx, err := ParseTx(raw)
		if err != nil {
			continue
		}
		push.Tx = append(push.Tx, tx)
		acked = append(acked, txid)
	}
	if len(push.Tx) == 0 {
		return
	}

	var pushBuf bytes.Buffer
	_, _ = protodelim.MarshalTo(&pushBuf, push)

	req2, _ := http.NewRequestWithContext(ctx, "POST", peerURL+"/peer/tx/push", &pushBuf)
	req2.Header.Set("Content-Type", "application/x-protobuf")
	resp2, err := e.cfg.HTTPClient.Do(req2)
	if err != nil || resp2 == nil {
		return
	}
	func() {
		defer resp2.Body.Close()
		if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
			acked = nil
		}
	}()
	if len(acked) == 0 {
		log.Printf("[gossip] peer=%s acked=0 done wallMs=%d (elapsed=%dms)", peerURL, time.Now().UnixMilli(), time.Now().UnixMilli()-gossipStart)
		return
	}

	log.Printf("[gossip] peer=%s acked=%d done wallMs=%d (elapsed=%dms)", peerURL, len(acked), time.Now().UnixMilli(), time.Now().UnixMilli()-gossipStart)
	e.recordGossipAck(bit, need, acked)
}

func (e *Engine) recordGossipAck(bit uint64, need int, acked [][32]byte) {
	if len(acked) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gossipMask == nil {
		e.gossipMask = make(map[[32]byte]uint64)
	}
	for _, id := range acked {
		e.gossipMask[id] |= bit
		if e.gossipPending != nil && bits.OnesCount64(e.gossipMask[id]) >= need {
			delete(e.gossipPending, id)
			delete(e.gossipMask, id)
		}
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

		// Load arb chain state into snapshot.
		snap.ArbHead, snap.ArbSeq = getArbChain(tx)
		if ss, _, err := getSignerSetInTx(tx); err == nil {
			snap.SignerSet = ss
		}
		// Inject arb chain as a synthetic AccountSnap so the generic prev/seq
		// checks in ValidateTxAgainstSnapshot work without special-casing.
		snap.Accounts[ArbChainID] = AccountSnap{
			Head: snap.ArbHead,
			Seq:  snap.ArbSeq,
		}

		return nil
	})
	return snap, err
}

// buildCandidateListV2 builds a txid-only candidate list ("votes").
// It ignores raws and uses e.approved (one tx per conflict key).
func (e *Engine) buildCandidateList(epoch uint64, snap *Snapshot) (*CandidateList, [][32]byte) {
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

func (e *Engine) finalizationQuorum(epoch uint64) (bestAccepted [32]byte, bestRoot [32]byte, count int, need int, txids [][32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	total := len(e.cfg.ValidatorSet)
	need = (total*e.cfg.FinalizationQuorumPercent + 99) / 100
	if need < 1 {
		need = 1
	}

	m := e.peerFinals[epoch]
	if m == nil {
		return [32]byte{}, [32]byte{}, 0, need, nil
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

	// Find the txid list from any finalization that matches the quorum winner
	var bestTxids [][32]byte
	for _, fin := range m {
		if fin == nil || fin.AcceptedTxidsHash == nil || fin.FrontiersRoot == nil {
			continue
		}
		var a [32]byte
		copy(a[:], fin.AcceptedTxidsHash.V)
		var r [32]byte
		copy(r[:], fin.FrontiersRoot.V)
		if a == bestK.accepted && r == bestK.root && len(fin.AcceptedTxids) > 0 {
			bestTxids = make([][32]byte, 0, len(fin.AcceptedTxids))
			for _, raw := range fin.AcceptedTxids {
				if len(raw) == 32 {
					var id [32]byte
					copy(id[:], raw)
					bestTxids = append(bestTxids, id)
				}
			}
			break
		}
	}

	return bestK.accepted, bestK.root, bestC, need, bestTxids
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

func (e *Engine) applyWinners(winners map[[32]byte][32]byte, txBytesByID map[[32]byte][]byte, parsed map[[32]byte]*pb.Tx) (map[[32]byte]struct{}, map[[32]byte]error, error) {
	applied := make(map[[32]byte]struct{})
	failed := make(map[[32]byte]error)

	err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		view := &bboltTxView{tx: tx}

		for _, id := range winners {
			raw := txBytesByID[id]
			p := parsed[id]

			if raw == nil || p == nil {
				if raw != nil {
					pp, perr := ParseTx(raw)
					if perr == nil {
						p = pp
					}
				}
			}
			if raw == nil || p == nil {
				failed[id] = errors.New("missing tx bytes/parse")
				continue
			}

			if aerr := ApplyTx(view, raw, p, id, e.cfg.FundAccount); aerr != nil {
				failed[id] = aerr
				continue
			}
			applied[id] = struct{}{}
			// log.Printf("APPLIED tx %x... acct=%x... seq=%d", id[:4], p.Account.V[:4], p.Seq)
		}
		return nil
	})

	return applied, failed, err
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

	log.Printf("[fetch] starting: need=%d peers=%d", len(missing), len(e.cfg.Peers))

	resolved := make(map[[32]byte]struct{})

	for i, peer := range e.cfg.Peers {
		// Build list of still-missing txids
		var still [][32]byte
		for _, id := range missing {
			if _, ok := resolved[id]; !ok {
				still = append(still, id)
			}
		}
		if len(still) == 0 {
			log.Printf("[fetch] all resolved after %d peers", i)
			break
		}

		peer = strings.TrimRight(peer, "/")
		log.Printf("[fetch] trying peer=%s still_missing=%d", peer, len(still))

		vid := e.cfg.Signer.PublicKeyCompressed()
		want := &pb.TxWant{
			Epoch: epoch,
			From:  &pb.Pub32{V: vid[:]},
		}
		for _, id := range still {
			want.Txid = append(want.Txid, &pb.Hash32{V: id[:]})
		}

		var buf bytes.Buffer
		_, _ = protodelim.MarshalTo(&buf, want)

		req, _ := http.NewRequest("POST", peer+"/peer/tx/get", &buf)
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := e.cfg.HTTPClient.Do(req)
		if err != nil || resp == nil {
			log.Printf("[fetch] peer=%s failed: %v", peer, err)
			continue
		}

		got := 0
		func() {
			defer resp.Body.Close()

			var push pb.TxPush
			br := bufio.NewReader(resp.Body)
			if err := protodelim.UnmarshalFrom(br, &push); err != nil {
				log.Printf("[fetch] peer=%s proto error: %v", peer, err)
				return
			}

			for _, tx := range push.Tx {
				if tx == nil {
					continue
				}
				raw, err := CanonicalTxBytes(tx)
				if err != nil {
					continue
				}
				if err := e.ReceiveGossipedTx(raw); err == nil {
					txid, _ := crypto.TxID(tx)
					resolved[txid] = struct{}{}
					got++
				}
			}
		}()

		log.Printf("[fetch] peer=%s returned=%d resolved_so_far=%d/%d", peer, got, len(resolved), len(missing))
	}

	log.Printf("[fetch] done: resolved=%d/%d", len(resolved), len(missing))
}

func (e *Engine) epochAtUnixMs(nowMs int64) uint64 {
	genesisMs := e.cfg.GenesisUnixMs
	epochMs := int64(e.cfg.EpochDuration / time.Millisecond)
	if epochMs <= 0 {
		epochMs = 1
	}
	return uint64((nowMs-genesisMs)/epochMs) + 1
}

func (e *Engine) epochNow() uint64 {
	return e.epochAtUnixMs(time.Now().UnixMilli())
}

func (e *Engine) cleanupAfterEpoch(
	epoch uint64,
	accepted map[[32]byte]struct{},
	failedApplied map[[32]byte]error,
	postSnap *Snapshot,
) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Option 2 (boundary-safe):
	// - Drop txs that were first seen in the epoch that just closed (seenEpoch <= epoch).
	//   This enforces: "if not accepted by an epoch, delete entirely" (no retry).
	// - Keep txs seen AFTER the boundary (seenEpoch > epoch). Those belong to the next epoch
	//   and have not been decided yet (so it's not a retry).
	// - Also drop any accepted-but-failed-applied txs to prevent "wins forever" loops.

	// If maps are nil, just clear per-epoch caches
	if e.txSeenEpoch == nil {
		if e.peerLists != nil {
			delete(e.peerLists, epoch)
		}
		if e.peerFinals != nil {
			delete(e.peerFinals, epoch)
		}
		return
	}

	// --- diagnostic: detect txs being dropped without ever being applied ---
	droppedUnapplied := 0
	for txid, seen := range e.txSeenEpoch {
		if seen <= epoch {
			if _, wasAccepted := accepted[txid]; !wasAccepted {
				if _, wasFailed := failedApplied[txid]; !wasFailed {
					droppedUnapplied++
				}
			}
		}
	}
	if droppedUnapplied > 0 {
		log.Printf("[epoch=%d] phase:cleanup WARNING dropping %d unapplied txs (never made it to any candidate list)", epoch, droppedUnapplied)
	}
	// --- end diagnostic ---

	// 1) Drop everything from the closed epoch window (seenEpoch <= epoch)
	for txid, seen := range e.txSeenEpoch {
		if seen <= epoch {
			delete(e.txSeenEpoch, txid)
			if e.txPool != nil {
				delete(e.txPool, txid)
			}
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
		}
	}

	// 2) Drop accepted-but-failed-applied (even if their seenEpoch was > epoch due to timing)
	for txid := range failedApplied {
		delete(e.txSeenEpoch, txid)
		if e.txPool != nil {
			delete(e.txPool, txid)
		}
		if e.gossipPending != nil {
			delete(e.gossipPending, txid)
		}
		if e.gossipMask != nil {
			delete(e.gossipMask, txid)
		}
	}

	// Drop applied txs no matter when they were "seen", to avoid re-advertising.
	for txid := range accepted {
		delete(e.txSeenEpoch, txid)
		if e.txPool != nil {
			delete(e.txPool, txid)
		}
		if e.gossipPending != nil {
			delete(e.gossipPending, txid)
		}
		if e.gossipMask != nil {
			delete(e.gossipMask, txid)
		}
	}

	// 3) Rebuild conflictPool + approved from remaining txPool,
	// but FIRST prune carry-over txs using post-commit snapshot tip rules:
	// carry only if prev==head AND seq==headSeq+1 (no pipelining).
	e.conflictPool = make(map[[32]byte][][32]byte)
	e.approved = make(map[[32]byte][32]byte)

	for txid, raw := range e.txPool {
		tx, err := ParseTx(raw)
		if err != nil {
			// malformed; drop it
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		// Must have account/prev to evaluate carry rule
		if tx.Account == nil || len(tx.Account.V) != 32 || tx.Prev == nil || len(tx.Prev.V) != 32 {
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		var acct [32]byte
		copy(acct[:], tx.Account.V)

		var prev [32]byte
		copy(prev[:], tx.Prev.V)

		// Unknown account defaults to zero head/seq.
		as, ok := postSnap.Accounts[acct]
		if !ok {
			as = AccountSnap{}
		}

		// Carry rule: prev==current head AND seq==current seq + 1
		if prev != as.Head || tx.Seq != as.Seq+1 {
			delete(e.txPool, txid)
			delete(e.txSeenEpoch, txid)
			if e.gossipPending != nil {
				delete(e.gossipPending, txid)
			}
			if e.gossipMask != nil {
				delete(e.gossipMask, txid)
			}
			continue
		}

		// Keep it: rebuild conflict structures for next epoch
		if key, ok := conflictKeyHash(tx); ok {
			e.conflictPool[key] = appendUnique32(e.conflictPool[key], txid)

			// Deterministic approval: lowest txid wins
			if cur, exists := e.approved[key]; !exists {
				e.approved[key] = txid
			} else if bytes.Compare(txid[:], cur[:]) < 0 {
				e.approved[key] = txid
			}
		}
	}

	// 4) Clear per-epoch caches so they don't grow forever
	if e.peerLists != nil {
		delete(e.peerLists, epoch)
	}
	if e.peerFinals != nil {
		delete(e.peerFinals, epoch)
	}

}

func (e *Engine) ensureGenesisOnBoot() error {
	gen := e.cfg.GenesisAccount
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}

		// --- Regular account genesis (unchanged logic) ---
		head, bal, seq := getAccount(tx, gen)
		var zero [32]byte
		if head == zero || seq < 1 {
			if bal == 0 {
				bal = e.cfg.GenesisSupply
			}
			h := sha256.Sum256(append([]byte("ANOS_GENESIS_HEAD_V1:"), gen[:]...))
			head = h
			if seq < 1 {
				seq = 1
			}
			if err := putAccount(tx, gen, head, bal, seq); err != nil {
				return err
			}
		}

		// --- Arbitrator genesis (idempotent and repairs partial state) ---
		if e.cfg.GenesisArbitratorPubkey == zero {
			return errors.New("GenesisArbitratorPubkey must be set (GENESIS_ARBITRATOR_HEX)")
		}

		ss, found, err := getSignerSetInTx(tx)
		if err != nil {
			return fmt.Errorf("read signer set: %w", err)
		}

		arbHead, arbSeq := getArbChain(tx)

		needSignerSet := !found || ss == nil || len(ss.Pubkeys) == 0
		needArbChain := arbHead == zero || arbSeq < 1

		if needSignerSet {
			ss = &pb.SignerSet{
				Pubkeys:   []*pb.Pub32{{V: append([]byte(nil), e.cfg.GenesisArbitratorPubkey[:]...)}},
				Threshold: 1,
			}
			if err := putSignerSet(tx, ss); err != nil {
				return err
			}
			log.Printf("[genesis] arb signer set bootstrapped key=%x", e.cfg.GenesisArbitratorPubkey[:4])
		}

		if needArbChain {
			arbGenesisHead := sha256.Sum256(append([]byte("ANOS_ARB_CHAIN_GENESIS_V1:"), ArbChainID[:]...))
			if err := putArbChain(tx, arbGenesisHead, 1); err != nil {
				return err
			}
			log.Printf("[genesis] arb chain bootstrapped head=%x seq=1", arbGenesisHead[:4])
		}

		return nil
	})
}
