package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	pb "anos/internal/proto"
)

var (
	BMeta           = []byte("meta")
	BAccounts       = []byte("accounts")
	BTxs            = []byte("txs")
	BRecv           = []byte("recv")
	BEpochFrontiers = []byte("epoch_frontiers")
	BFinalizations  = []byte("finalizations")
	BSignerSets     = []byte("signer_sets") // key: ArbChainID(32) -> proto SignerSet (fast-access cache)
	BArbChain       = []byte("arb_chain")   // key: ArbChainID(32) -> head(32) || seq(u64 BE)
)

var (
	ErrNotFound = errors.New("not found")
)

func ensureBuckets(tx *bbolt.Tx) error {
	for _, b := range [][]byte{BMeta, BAccounts, BTxs, BRecv, BEpochFrontiers, BFinalizations, BSignerSets, BArbChain} {
		if _, err := tx.CreateBucketIfNotExists(b); err != nil {
			return err
		}
	}
	return nil
}

func packAccount(head [32]byte, balance uint64, seq uint64) []byte {
	out := make([]byte, 32+8+8)
	copy(out[:32], head[:])
	binary.BigEndian.PutUint64(out[32:40], balance)
	binary.BigEndian.PutUint64(out[40:48], seq)
	return out
}

func unpackAccount(v []byte) (head [32]byte, bal uint64, seq uint64, ok bool) {
	if len(v) != 32+8+8 {
		return [32]byte{}, 0, 0, false
	}
	copy(head[:], v[:32])
	bal = binary.BigEndian.Uint64(v[32:40])
	seq = binary.BigEndian.Uint64(v[40:48])
	return head, bal, seq, true
}

func getAccount(tx *bbolt.Tx, acct [32]byte) (head [32]byte, bal uint64, seq uint64) {
	b := tx.Bucket(BAccounts)
	if b == nil {
		return [32]byte{}, 0, 0
	}
	v := b.Get(acct[:])
	if v == nil {
		return [32]byte{}, 0, 0
	}
	h, bbal, sseq, ok := unpackAccount(v)
	if !ok {
		return [32]byte{}, 0, 0
	}
	return h, bbal, sseq
}

func putAccount(tx *bbolt.Tx, acct [32]byte, head [32]byte, bal uint64, seq uint64) error {
	return tx.Bucket(BAccounts).Put(acct[:], packAccount(head, bal, seq))
}

func putTxRaw(tx *bbolt.Tx, txid [32]byte, raw []byte) error {
	return tx.Bucket(BTxs).Put(txid[:], raw)
}

func getTxRaw(tx *bbolt.Tx, txid [32]byte) ([]byte, error) {
	v := tx.Bucket(BTxs).Get(txid[:])
	if v == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func hasTx(tx *bbolt.Tx, txid [32]byte) bool {
	return tx.Bucket(BTxs).Get(txid[:]) != nil
}

func putReceivableRaw(tx *bbolt.Tx, rid [32]byte, raw []byte) error {
	return tx.Bucket(BRecv).Put(rid[:], raw)
}

func getReceivableRaw(tx *bbolt.Tx, rid [32]byte) ([]byte, error) {
	v := tx.Bucket(BRecv).Get(rid[:])
	if v == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func hasReceivable(tx *bbolt.Tx, rid [32]byte) bool {
	return tx.Bucket(BRecv).Get(rid[:]) != nil
}

func bytesEq32(a []byte, b [32]byte) bool { return len(a) == 32 && bytes.Equal(a, b[:]) }

type AccountHeadRow struct {
	Account [32]byte
	Head    [32]byte
	Balance uint64
	Seq     uint64
}

// ListAllAccountHeads reads the current heads for all accounts from the DB.
// It returns one row per account in the BAccounts bucket.
func ListAllAccountHeads(db *bbolt.DB) ([]AccountHeadRow, error) {
	var out []AccountHeadRow

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BAccounts)
		if b == nil {
			// If buckets weren’t created yet, treat as empty.
			return nil
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 32 {
				continue
			}
			head, bal, seq, ok := unpackAccount(v)
			if !ok {
				continue
			}

			var acct [32]byte
			copy(acct[:], k)

			out = append(out, AccountHeadRow{
				Account: acct,
				Head:    head,
				Balance: bal,
				Seq:     seq,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Stable ordering (helpful for debugging / diffing)
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].Account[:], out[j].Account[:]) < 0
	})

	return out, nil
}

// --- Finalizations ---

func finalKey(epoch uint64, validatorID [33]byte) []byte {
	k := make([]byte, 8+33)
	binary.BigEndian.PutUint64(k[:8], epoch)
	copy(k[8:], validatorID[:])
	return k
}

func PutFinalization(tx *bbolt.Tx, epoch uint64, validatorID [33]byte, raw []byte) error {
	return tx.Bucket(BFinalizations).Put(finalKey(epoch, validatorID), raw)
}

func GetFinalizations(db *bbolt.DB, epoch uint64) ([][]byte, error) {
	var out [][]byte
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BFinalizations)
		if b == nil {
			return ErrNotFound
		}
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, epoch)

		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			out = append(out, append([]byte(nil), v...))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// --- Epoch frontiers (acct->head snapshot after apply) ---

func epochFrontierKey(epoch uint64, acct [32]byte) []byte {
	k := make([]byte, 8+32)
	binary.BigEndian.PutUint64(k[:8], epoch)
	copy(k[8:], acct[:])
	return k
}

// SaveEpochFrontiers snapshots the current BAccounts heads into BEpochFrontiers for this epoch.
// Call this immediately after applying winners (post-state).
func SaveEpochFrontiers(db *bbolt.DB, epoch uint64) error {
	return db.Update(func(tx *bbolt.Tx) error {
		if err := ensureBuckets(tx); err != nil {
			return err
		}
		acc := tx.Bucket(BAccounts)
		out := tx.Bucket(BEpochFrontiers)

		c := acc.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 32 {
				continue
			}
			head, _, _, ok := unpackAccount(v)
			if !ok {
				continue
			}
			var acct [32]byte
			copy(acct[:], k)
			if err := out.Put(epochFrontierKey(epoch, acct), head[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

type FrontierEntry struct {
	AccountID [32]byte
	HeadHash  [32]byte
}

func IterEpochFrontiers(db *bbolt.DB, epoch uint64, cursor [32]byte, limit int) ([]FrontierEntry, *[32]byte, error) {
	if limit <= 0 {
		limit = 1000
	}
	var entries []FrontierEntry
	var next *[32]byte

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BEpochFrontiers)
		if b == nil {
			return ErrNotFound
		}
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, epoch)

		seek := prefix
		if cursor != ([32]byte{}) {
			seek = epochFrontierKey(epoch, cursor)
		}

		c := b.Cursor()
		for k, v := c.Seek(seek); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(k) != 8+32 || len(v) != 32 {
				continue
			}
			var acct [32]byte
			copy(acct[:], k[8:40])
			var head [32]byte
			copy(head[:], v)

			entries = append(entries, FrontierEntry{AccountID: acct, HeadHash: head})
			if len(entries) >= limit {
				// next cursor is the next account id (if any)
				nk, _ := c.Next()
				if nk != nil && bytes.HasPrefix(nk, prefix) && len(nk) >= 40 {
					var nc [32]byte
					copy(nc[:], nk[8:40])
					next = &nc
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return entries, next, nil
}

// ComputeFrontiersRoot computes SHA256 of concat(sorted(account||head)) for epoch frontiers.
func ComputeFrontiersRoot(db *bbolt.DB, epoch uint64) ([32]byte, error) {
	var rows []FrontierEntry
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BEpochFrontiers)
		if b == nil {
			return ErrNotFound
		}
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, epoch)

		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(k) != 8+32 || len(v) != 32 {
				continue
			}
			var acct [32]byte
			copy(acct[:], k[8:40])
			var head [32]byte
			copy(head[:], v)
			rows = append(rows, FrontierEntry{AccountID: acct, HeadHash: head})
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}

	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].AccountID[:], rows[j].AccountID[:]) < 0
	})

	h := sha256.New()
	var buf [64]byte
	for _, r := range rows {
		copy(buf[:32], r.AccountID[:])
		copy(buf[32:], r.HeadHash[:])
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ComputeDryRunFrontiersRoot computes what the frontiers root would be if the
// given winners were applied, without actually writing to the DB.
// winners maps account -> txid (the new head after apply).
func ComputeDryRunFrontiersRoot(db *bbolt.DB, winners map[[32]byte][32]byte) ([32]byte, error) {
	// 1. Read all current account->head pairs from DB
	frontiers := make(map[[32]byte][32]byte)
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BAccounts)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 32 {
				continue
			}
			head, _, _, ok := unpackAccount(v)
			if !ok {
				continue
			}
			var acct [32]byte
			copy(acct[:], k)
			frontiers[acct] = head
		}
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}

	// 2. Overlay winners: for each winner, new head = txid
	for acct, txid := range winners {
		frontiers[acct] = txid
	}

	// 3. Sort and hash (same algorithm as ComputeFrontiersRoot)
	rows := make([]FrontierEntry, 0, len(frontiers))
	for acct, head := range frontiers {
		rows = append(rows, FrontierEntry{AccountID: acct, HeadHash: head})
	}
	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].AccountID[:], rows[j].AccountID[:]) < 0
	})

	h := sha256.New()
	var buf [64]byte
	for _, r := range rows {
		copy(buf[:32], r.AccountID[:])
		copy(buf[32:], r.HeadHash[:])
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ArbChainID is the well-known 32-byte key for the arbitrator chain in BArbChain and BSignerSets.
// It is SHA256("ANOS_ARB_CHAIN_V1") — a deterministic constant shared by all validators.
var ArbChainID = func() [32]byte {
	return sha256.Sum256([]byte("ANOS_ARB_CHAIN_V1"))
}()

func packArbChain(head [32]byte, seq uint64) []byte {
	out := make([]byte, 40)
	copy(out[:32], head[:])
	binary.BigEndian.PutUint64(out[32:40], seq)
	return out
}

func unpackArbChain(v []byte) (head [32]byte, seq uint64, ok bool) {
	if len(v) != 40 {
		return [32]byte{}, 0, false
	}
	copy(head[:], v[:32])
	return head, binary.BigEndian.Uint64(v[32:40]), true
}

func getArbChain(tx *bbolt.Tx) (head [32]byte, seq uint64) {
	b := tx.Bucket(BArbChain)
	if b == nil {
		return [32]byte{}, 0
	}
	id := ArbChainID
	v := b.Get(id[:])
	if v == nil {
		return [32]byte{}, 0
	}
	h, s, ok := unpackArbChain(v)
	if !ok {
		return [32]byte{}, 0
	}
	return h, s
}

func putArbChain(tx *bbolt.Tx, head [32]byte, seq uint64) error {
	id := ArbChainID
	return tx.Bucket(BArbChain).Put(id[:], packArbChain(head, seq))
}

// GetSignerSet reads the current SignerSet from BSignerSets. Returns nil if not initialised.
func GetSignerSet(db *bbolt.DB) (*pb.SignerSet, error) {
	var ss pb.SignerSet
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(BSignerSets)
		if b == nil {
			return ErrNotFound
		}
		id := ArbChainID
		raw := b.Get(id[:])
		if raw == nil {
			return ErrNotFound
		}
		return proto.Unmarshal(raw, &ss)
	})
	if err != nil {
		return nil, err
	}
	return &ss, nil
}

func putSignerSet(tx *bbolt.Tx, ss *pb.SignerSet) error {
	raw, err := proto.Marshal(ss)
	if err != nil {
		return err
	}
	id := ArbChainID
	return tx.Bucket(BSignerSets).Put(id[:], raw)
}

// getSignerSetInTx reads the SignerSet within an existing bbolt transaction.
func getSignerSetInTx(tx *bbolt.Tx) (*pb.SignerSet, error) {
	b := tx.Bucket(BSignerSets)
	if b == nil {
		return nil, ErrNotFound
	}
	id := ArbChainID
	raw := b.Get(id[:])
	if raw == nil {
		return nil, ErrNotFound
	}
	var ss pb.SignerSet
	if err := proto.Unmarshal(raw, &ss); err != nil {
		return nil, err
	}
	return &ss, nil
}
