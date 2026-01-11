package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
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

	Peers          []string
	EpochDuration  time.Duration
	QuorumPercent  int // used only for conflict resolution
	HTTPClient     *http.Client
	CandidatesSkew time.Duration

	FundAccount [32]byte
}

type Engine struct {
	cfg EngineConfig

	mu      sync.Mutex
	mempool [][]byte
	// epoch -> validator_id -> candidate list
	peerLists map[uint64]map[[33]byte]*CandidateList

	startOnce sync.Once
}

type CandidateList struct {
	Epoch       uint64
	ValidatorID [33]byte
	ListHash    [32]byte
	SigDER      []byte   // ASN.1 DER ECDSA signature
	Txs         [][]byte // raw protobuf-encoded pb.Tx messages
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
	if cfg.QuorumPercent == 0 {
		cfg.QuorumPercent = 80
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 2 * time.Second}
	}
	if cfg.CandidatesSkew == 0 {
		cfg.CandidatesSkew = 300 * time.Millisecond
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

	e.mu.Lock()
	defer e.mu.Unlock()
	e.mempool = append(e.mempool, append([]byte(nil), raw...))
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

	// 2) recompute txids and canonical list hash
	txids := make([][32]byte, 0, len(cl.Txs))
	for _, raw := range cl.Txs {
		tx, err := ParseTx(raw)
		if err != nil {
			return errors.New("bad tx in candidate list")
		}
		id, err := crypto.TxID(tx)
		if err != nil {
			return errors.New("bad txid")
		}
		txids = append(txids, id)
	}
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

// loop runs epochs.
func (e *Engine) loop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.EpochDuration)
	defer ticker.Stop()

	var epoch uint64 = 1

	for {
		epochSnap, _ := e.buildSnapshot()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Close: build our candidate list from txs received during this epoch window.
		localRaw := e.drainMempool()
		selfList, _ := e.buildCandidateList(epoch, localRaw, epochSnap)

		// Broadcast once at epoch close
		e.broadcastCandidates(epoch, selfList)

		// Wait a small skew for peers to arrive
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.cfg.CandidatesSkew):
		}

		peerLists := e.getPeerLists(epoch)

		// Model B: Merge union of all valid txs; vote only within conflicts.
		totalValidators := len(e.cfg.ValidatorSet)
		threshold := (totalValidators*e.cfg.QuorumPercent + 99) / 100 // ceil
		if threshold < 1 {
			threshold = 1
		}

		// Union: txid -> raw, and txid support count (how many lists contained it)
		support := make(map[[32]byte]int)
		txBytesByID := make(map[[32]byte][]byte)

		// self list contributes support=1 for its txs
		selfTxIDs, selfByID := e.txIDsFromCandidateList(selfList)
		for _, id := range selfTxIDs {
			support[id]++
			if _, ok := txBytesByID[id]; !ok {
				txBytesByID[id] = selfByID[id]
			}
		}

		for _, cl := range peerLists {
			ids, by := e.txIDsFromCandidateList(cl)
			for _, id := range ids {
				support[id]++
				if _, ok := txBytesByID[id]; !ok {
					txBytesByID[id] = by[id]
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

		_ = e.applyWinners(winners, txBytesByID, validParsed)

		epoch++
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

// buildCandidateList includes ALL valid txs seen during epoch (even conflicting), per Model B.
func (e *Engine) buildCandidateList(epoch uint64, raws [][]byte, snap *Snapshot) (*CandidateList, [][32]byte) {
	type item struct {
		id  [32]byte
		raw []byte
	}
	items := make([]item, 0, len(raws))
	for _, raw := range raws {
		tx, err := ParseTx(raw)
		if err != nil {
			continue
		}
		id, err := ValidateTxAgainstSnapshot(tx, snap)
		if err != nil {
			continue
		}
		items = append(items, item{id: id, raw: raw})
	}

	// Sort by txid for stable list_hash/signature
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].id[:], items[j].id[:]) < 0 })

	ids := make([][32]byte, 0, len(items))
	txs := make([][]byte, 0, len(items))

	for _, it := range items {
		ids = append(ids, it.id)
		txs = append(txs, it.raw)
	}

	listHash := crypto.CandidatesListHash(ids)

	vid := e.cfg.Signer.PublicKeyCompressed()

	digest := crypto.CandidatesDigestP256(epoch, vid, listHash)
	sigDER, err := e.cfg.Signer.SignDigest(digest)
	if err != nil {
		// return unsigned list; peers will reject, but avoids panic
		sigDER = nil
	}

	cl := &CandidateList{
		Epoch:       epoch,
		ValidatorID: vid,
		ListHash:    listHash,
		SigDER:      sigDER,
		Txs:         txs,
	}

	return cl, ids

}

func (e *Engine) broadcastCandidates(epoch uint64, cl *CandidateList) {
	// Encode as a deterministic protobuf-delimited stream:
	// [Pub32 validator_id][EpochRecord {epoch, accepted_txs=list_hash_placeholder}][Sig64 sig][Tx...]
	// We do not need to send list_hash separately because receivers recompute it from txids and verify the signature.
	// We send it anyway as a fixed field in CandidateList for debugging; over the wire we include it as 32 bytes in the EpochRecord.state_root field.
	buf := &bytes.Buffer{}

	// 1) validator id
	_, _ = protodelim.MarshalTo(buf, &pb.Pub32{V: cl.ValidatorID[:]})

	// 2) epoch + list_hash (carried in state_root for transport convenience)
	er := &pb.EpochRecord{
		Epoch:     cl.Epoch,
		StateRoot: &pb.Hash32{V: cl.ListHash[:]},
	}
	_, _ = protodelim.MarshalTo(buf, er)

	// 3) signature
	_, _ = protodelim.MarshalTo(buf, &pb.Sig64{V: cl.SigDER})

	// 4) txs (full bodies)
	for _, raw := range cl.Txs {
		tx, err := ParseTx(raw)
		if err != nil {
			continue
		}
		_, _ = protodelim.MarshalTo(buf, tx)
	}

	body := buf.Bytes()
	for _, peer := range e.cfg.Peers {
		peer = strings.TrimRight(peer, "/")
		go func(p string) {
			req, _ := http.NewRequest("POST", p+"/peer/candidates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/x-protobuf")
			_, _ = e.cfg.HTTPClient.Do(req)
		}(peer)
	}
	_ = epoch
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

// txIDsFromCandidateList decodes tx bytes and computes txids.
func (e *Engine) txIDsFromCandidateList(cl *CandidateList) ([][32]byte, map[[32]byte][]byte) {
	ids := make([][32]byte, 0, len(cl.Txs))
	byID := make(map[[32]byte][]byte, len(cl.Txs))
	for _, raw := range cl.Txs {
		tx, err := ParseTx(raw)
		if err != nil {
			continue
		}
		id, err := crypto.TxID(tx)
		if err != nil {
			continue
		}
		ids = append(ids, id)
		byID[id] = raw
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	return ids, byID
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
