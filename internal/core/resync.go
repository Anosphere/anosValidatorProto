package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

// ResyncState is stored on Engine and guarded by e.mu.
// Keep it tiny: just enough to pause epochs, run a single resync, and return to normal.
type ResyncState struct {
	Mode          ResyncMode
	MismatchEpoch uint64
	WantAccepted  [32]byte
	WantRoot      [32]byte
	LastErr       string
	LastPeer      string
	LastTargetEp  uint64
}

type ResyncMode uint8

const (
	ResyncIdle ResyncMode = iota
	ResyncPending
	ResyncRunning
)

func (rs ResyncState) IsActive() bool {
	return rs.Mode != ResyncIdle
}

// triggerResync moves the engine into resync mode.
// It is intentionally idempotent (first mismatch wins).
func (e *Engine) triggerResync(mismatchEpoch uint64, wantAccepted [32]byte, wantRoot [32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.resync.Mode != ResyncIdle {
		return
	}
	e.resync.Mode = ResyncPending
	e.resync.MismatchEpoch = mismatchEpoch
	e.resync.WantAccepted = wantAccepted
	e.resync.WantRoot = wantRoot
	e.resync.LastErr = ""
}

// runResync performs a full rebuild from a peer using the existing /sync/* endpoints.
// It returns nil on success (engine returns to normal operation).
func (e *Engine) runResync(ctx context.Context) error {
	e.mu.Lock()
	mode := e.resync.Mode
	mismatchEpoch := e.resync.MismatchEpoch
	wantAccepted := e.resync.WantAccepted
	wantRoot := e.resync.WantRoot
	e.resync.Mode = ResyncRunning
	e.mu.Unlock()

	if mode == ResyncIdle {
		return nil
	}

	start := time.Now()

	peer, targetEp, qAccepted, qRoot, qCount, qNeed, err := e.pickResyncTarget(ctx, mismatchEpoch)
	if err != nil {
		e.setResyncError(err)
		e.elog(mismatchEpoch, "RESYNC failed (pick target): %v", err)
		return err
	}

	// If we were triggered by a mismatch and the quorum-best hashes don't match the target,
	// stick to the quorum result from the peer.
	_ = wantAccepted
	_ = wantRoot

	e.elog(mismatchEpoch, "RESYNC starting: peer=%s targetEpoch=%d quorum=%d/%d", peer, targetEp, qCount, qNeed)

	frontiers, err := e.fetchAllFrontiers(ctx, peer, targetEp)
	if err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (frontiers): %v", err)
		return err
	}

	// Rebuild local DB from scratch to exactly match the peer's target epoch.
	if err := e.rebuildFromFrontiers(ctx, peer, targetEp, frontiers); err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (rebuild): %v", err)
		return err
	}

	// Save + verify root against quorum target.
	if err := SaveEpochFrontiers(e.cfg.DB, targetEp); err != nil {
		e.setResyncError(fmt.Errorf("resync: SaveEpochFrontiers: %w", err))
		return err
	}
	root, err := ComputeFrontiersRoot(e.cfg.DB, targetEp)
	if err != nil {
		e.setResyncError(fmt.Errorf("resync: ComputeFrontiersRoot: %w", err))
		return err
	}
	if root != qRoot {
		e.setResyncError(fmt.Errorf("resync: root mismatch after rebuild: have=%x want=%x", root[:], qRoot[:]))
		e.elog(targetEp, "RESYNC failed (root mismatch): have=%x want=%x", root[:], qRoot[:])
		return errors.New("resync root mismatch")
	}

	// Persist the peer's finalizations for the target epoch so /sync/latest is meaningful.
	if err := e.persistPeerFinalizations(ctx, peer, targetEp); err != nil {
		e.setResyncError(err)
		e.elog(targetEp, "RESYNC failed (persist finalizations): %v", err)
		return err
	}

	// Clear volatile in-memory pools (we've rebuilt canonical state).
	e.mu.Lock()
	e.txPool = make(map[[32]byte][]byte)
	e.txSeenEpoch = make(map[[32]byte]uint64)
	e.conflictPool = make(map[[32]byte][][32]byte)
	e.approved = make(map[[32]byte][32]byte)
	e.gossipPending = make(map[[32]byte]struct{})
	e.peerLists = make(map[uint64]map[[33]byte]*CandidateList)
	e.peerFinals = make(map[uint64]map[[33]byte]*pb.EpochFinalization)

	e.resync = ResyncState{
		Mode:         ResyncIdle,
		LastErr:      "",
		LastPeer:     peer,
		LastTargetEp: targetEp,
		WantAccepted: qAccepted,
		WantRoot:     qRoot,
	}
	e.resyncNextAttempt = time.Time{}
	e.resyncFailCount = 0
	e.mu.Unlock()

	e.elog(targetEp, "RESYNC complete: peer=%s root=%x... (elapsed=%s)", peer, root[:4], time.Since(start).Truncate(time.Millisecond))
	return nil
}

func (e *Engine) setResyncError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resync.LastErr = err.Error()
	// Keep Mode=Pending so loop will retry next tick/epoch.
	e.resync.Mode = ResyncPending

	// Exponential-ish backoff capped.
	e.resyncFailCount++
	delay := time.Duration(1<<minInt(e.resyncFailCount, 5)) * time.Second // 2s..32s
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	e.resyncNextAttempt = time.Now().Add(delay)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// pickResyncTarget chooses a peer + target epoch and computes quorum-best hashes for that epoch.
//
// This is intentionally minimal:
// - We pick the peer reporting the highest /sync/latest.
// - Then we pull /sync/finalization for that epoch and compute the quorum-best pair.
func (e *Engine) pickResyncTarget(ctx context.Context, mismatchEpoch uint64) (peer string, targetEp uint64, qAccepted [32]byte, qRoot [32]byte, qCount int, qNeed int, err error) {
	bestEp := uint64(0)
	bestPeer := ""
	for _, p := range e.cfg.Peers {
		p = strings.TrimRight(p, "/")
		ep, e2 := e.httpSyncLatest(ctx, p)
		if e2 != nil {
			continue
		}
		if ep > bestEp {
			bestEp = ep
			bestPeer = p
		}
	}
	if bestPeer == "" {
		return "", 0, [32]byte{}, [32]byte{}, 0, 0, errors.New("resync: no reachable peers")
	}
	if bestEp < mismatchEpoch {
		bestEp = mismatchEpoch
	}

	fins, e3 := e.httpSyncFinalization(ctx, bestPeer, bestEp)
	if e3 != nil {
		return "", 0, [32]byte{}, [32]byte{}, 0, 0, e3
	}
	qAccepted, qRoot, qCount, qNeed = finalizationQuorumFromFins(e.cfg.ValidatorSet, bestEp, fins, e.cfg.FinalizationQuorumPercent)
	if qCount < qNeed {
		return "", 0, [32]byte{}, [32]byte{}, qCount, qNeed, fmt.Errorf("resync: finalization quorum not available at target epoch %d (%d/%d)", bestEp, qCount, qNeed)
	}
	return bestPeer, bestEp, qAccepted, qRoot, qCount, qNeed, nil
}

func finalizationQuorumFromFins(vset map[[33]byte]*ecdsa.PublicKey, epoch uint64, fins []*pb.EpochFinalization, pct int) (bestAccepted [32]byte, bestRoot [32]byte, count int, need int) {
	_ = epoch

	total := len(vset)
	need = (total*pct + 99) / 100
	if need < 1 {
		need = 1
	}

	type key struct {
		a [32]byte
		r [32]byte
	}
	counts := make(map[key]int)

	for _, fin := range fins {
		if fin == nil || fin.Signer == nil || len(fin.Signer.V) != 33 {
			continue
		}
		var signer [33]byte
		copy(signer[:], fin.Signer.V)
		pub := vset[signer]
		if pub == nil {
			continue
		}
		if fin.AcceptedTxidsHash == nil || len(fin.AcceptedTxidsHash.V) != 32 || fin.FrontiersRoot == nil || len(fin.FrontiersRoot.V) != 32 || fin.Sig == nil {
			continue
		}
		var a [32]byte
		copy(a[:], fin.AcceptedTxidsHash.V)
		var r [32]byte
		copy(r[:], fin.FrontiersRoot.V)
		digest := crypto.FinalizationDigestP256(fin.Epoch, a, r)
		if !crypto.VerifyFinalizationSigP256(pub, digest, fin.Sig.V) {
			continue
		}
		counts[key{a: a, r: r}]++
	}

	best := key{}
	bestC := 0
	for k, c := range counts {
		if c > bestC {
			best = k
			bestC = c
		}
	}
	return best.a, best.r, bestC, need
}

// fetchAllFrontiers pulls /sync/frontiers pages until complete.
func (e *Engine) fetchAllFrontiers(ctx context.Context, peer string, epoch uint64) (map[[32]byte][32]byte, error) {
	peer = strings.TrimRight(peer, "/")
	out := make(map[[32]byte][32]byte)
	var cursor [32]byte
	for {
		resp, err := e.httpSyncFrontiers(ctx, peer, epoch, cursor, 1000)
		if err != nil {
			return nil, err
		}
		for _, ent := range resp.Entries {
			if ent == nil || ent.Account == nil || len(ent.Account.V) != 32 || ent.Head == nil || len(ent.Head.V) != 32 {
				continue
			}
			var acct [32]byte
			copy(acct[:], ent.Account.V)
			var head [32]byte
			copy(head[:], ent.Head.V)
			out[acct] = head
		}
		if resp.NextCursor == nil || len(resp.NextCursor.V) != 32 {
			break
		}
		copy(cursor[:], resp.NextCursor.V)
	}
	return out, nil
}

// rebuildFromFrontiers wipes local state buckets and replays chains for every frontier account.
func (e *Engine) rebuildFromFrontiers(ctx context.Context, peer string, targetEp uint64, frontiers map[[32]byte][32]byte) error {
	peer = strings.TrimRight(peer, "/")

	// 1) wipe state buckets
	if err := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		// delete and recreate mutable buckets
		for _, b := range [][]byte{BAccounts, BTxs, BRecv, BEpochFrontiers, BFinalizations} {
			_ = tx.DeleteBucket(b)
			if _, err := tx.CreateBucket(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("resync: wipe buckets: %w", err)
	}

	// 2) restore genesis anchor
	if err := e.ensureGenesisOnBoot(); err != nil {
		return fmt.Errorf("resync: ensure genesis: %w", err)
	}

	// 3) download chains for each account
	type chain struct {
		acct [32]byte
		raws [][]byte // forward order (oldest -> newest)
		idx  int
	}

	chains := make([]*chain, 0, len(frontiers))
	for acct, head := range frontiers {
		// Skip zero head
		if head == ([32]byte{}) {
			continue
		}
		// Request a large max; if the peer has more than this, caller can increase later.
		// Determine the correct chain boundary ("have") for this account.
		// For normal accounts this is zero; for the fund/genesis-anchored account
		// it's the synthetic genesis head set during ensureGenesisOnBoot().
		haveBoundary := [32]byte{}
		_ = e.cfg.DB.View(func(tx *bbolt.Tx) error {
			// ensureBuckets not strictly required here if you know they exist,
			// but harmless and keeps things consistent.
			if err := ensureBuckets(tx); err != nil {
				return err
			}
			h, _, _ := getAccount(tx, acct)
			haveBoundary = h // zero for normal accounts; synthetic anchor for fund/genesis account
			return nil
		})

		txsBack, reached, err := e.httpSyncChain(ctx, peer, acct, head, haveBoundary, 200000)
		if err != nil {
			return err
		}
		if !reached {
			return fmt.Errorf("resync: chain for acct %x... did not reach boundary have=%x (increase MaxBlocks)", acct[:4], haveBoundary[:4])
		}
		// reverse to forward
		for i, j := 0, len(txsBack)-1; i < j; i, j = i+1, j-1 {
			txsBack[i], txsBack[j] = txsBack[j], txsBack[i]
		}
		chains = append(chains, &chain{acct: acct, raws: txsBack})
	}

	// Deterministic order for reproducible logs
	sort.Slice(chains, func(i, j int) bool { return bytes.Compare(chains[i].acct[:], chains[j].acct[:]) < 0 })

	// 4) dependency-aware apply loop
	// We repeatedly try to apply the next tx from each account chain.
	// - Prev/seq constraints are enforced by ApplyTx.
	// - RECEIVE dependencies are enforced by ApplyTx (receivable must exist).
	// This naturally topologically-sorts SEND->RECEIVE without needing epoch info.
	remaining := 0
	for _, c := range chains {
		remaining += len(c.raws)
	}

	for remaining > 0 {
		progress := 0
		for _, c := range chains {
			if c.idx >= len(c.raws) {
				continue
			}
			raw := c.raws[c.idx]
			ptx, err := ParseTx(raw)
			if err != nil {
				return fmt.Errorf("resync: parse tx: %w", err)
			}
			txid, err := crypto.TxID(ptx)
			if err != nil {
				return fmt.Errorf("resync: txid: %w", err)
			}

			applyErr := e.cfg.DB.Update(func(tx *bbolt.Tx) error {
				if err := ensureBuckets(tx); err != nil {
					return err
				}
				view := &bboltTxView{tx: tx}
				return ApplyTx(view, raw, ptx, txid, e.cfg.FundAccount)
			})
			if applyErr != nil {
				// Not-ready errors are expected during dependency resolution.
				// We only treat truly-fatal errors as abort.
				switch {
				case errors.Is(applyErr, ErrUnknownRecv), errors.Is(applyErr, ErrBadPrev), errors.Is(applyErr, ErrBadSeq):
					continue
				default:
					return fmt.Errorf("resync: apply acct=%x... tx=%x...: %v", c.acct[:4], txid[:4], applyErr)
				}
			}

			c.idx++
			remaining--
			progress++
		}
		if progress == 0 {
			// Stuck: dump a small hint for debugging.
			for _, c := range chains {
				if c.idx >= len(c.raws) {
					continue
				}
				raw := c.raws[c.idx]
				ptx, _ := ParseTx(raw)
				if ptx != nil {
					return fmt.Errorf("resync: stuck (no progress). next pending acct=%x... seq=%d type=%v prev=%s", c.acct[:4], ptx.Seq, ptx.Type, shortHex32(ptx.Prev))
				}
			}
			return errors.New("resync: stuck (no progress)")
		}
	}

	_ = targetEp
	return nil
}

func shortHex32(h *pb.Hash32) string {
	if h == nil || len(h.V) != 32 {
		return "<nil>"
	}
	return hex.EncodeToString(h.V[:4]) + "..."
}

func (e *Engine) persistPeerFinalizations(ctx context.Context, peer string, epoch uint64) error {
	fins, err := e.httpSyncFinalization(ctx, strings.TrimRight(peer, "/"), epoch)
	if err != nil {
		return err
	}
	return e.cfg.DB.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		for _, fin := range fins {
			if fin == nil || fin.Signer == nil || len(fin.Signer.V) != 33 {
				continue
			}
			var signerID [33]byte
			copy(signerID[:], fin.Signer.V)
			raw, err := proto.Marshal(fin)
			if err != nil {
				continue
			}
			if err := PutFinalization(tx, epoch, signerID, raw); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- HTTP helpers (protobuf over protodelim) ----

func (e *Engine) httpSyncLatest(ctx context.Context, peer string) (uint64, error) {
	peer = strings.TrimRight(peer, "/")
	req, _ := http.NewRequestWithContext(ctx, "GET", peer+"/sync/latest", nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("sync/latest %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncLatestResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return 0, err
	}
	return out.LatestEpoch, nil
}

func (e *Engine) httpSyncFinalization(ctx context.Context, peer string, epoch uint64) ([]*pb.EpochFinalization, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/finalization?epoch=%d", peer, epoch)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sync/finalization %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncFinalizationResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, err
	}
	return out.Finalizations, nil
}

func (e *Engine) httpSyncFrontiers(ctx context.Context, peer string, epoch uint64, cursor [32]byte, limit int) (*pb.SyncFrontiersResponse, error) {
	peer = strings.TrimRight(peer, "/")
	url := fmt.Sprintf("%s/sync/frontiers?epoch=%d&limit=%d", peer, epoch, limit)
	if cursor != ([32]byte{}) {
		url += "&cursor=" + hex.EncodeToString(cursor[:])
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sync/frontiers %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncFrontiersResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (e *Engine) httpSyncChain(ctx context.Context, peer string, acct [32]byte, targetHead [32]byte, have [32]byte, max int) ([][]byte, bool, error) {
	peer = strings.TrimRight(peer, "/")
	reqMsg := &pb.SyncChainRequest{
		Account:    &pb.AccountId{V: acct[:]},
		TargetHead: &pb.Hash32{V: targetHead[:]},
		MaxBlocks:  uint32(max),
	}
	if have != ([32]byte{}) {
		reqMsg.Have = &pb.Hash32{V: have[:]}
	}
	var buf bytes.Buffer
	_, _ = protodelim.MarshalTo(&buf, reqMsg)

	req, _ := http.NewRequestWithContext(ctx, "POST", peer+"/sync/chain", &buf)
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("sync/chain %s: %s body=%q", peer, resp.Status, string(b))
	}
	var out pb.SyncChainResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(resp.Body), &out); err != nil {
		return nil, false, err
	}

	// Convert pb.Tx -> canonical bytes so we store/execute a single wire format everywhere.
	ret := make([][]byte, 0, len(out.Tx))
	for _, tx := range out.Tx {
		if tx == nil {
			continue
		}
		raw, err := CanonicalTxBytes(tx)
		if err != nil {
			return nil, false, err
		}
		ret = append(ret, raw)
	}
	return ret, out.ReachedHave, nil
}
