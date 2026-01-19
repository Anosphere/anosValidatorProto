package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"go.etcd.io/bbolt"
)

var (
	BMeta     = []byte("meta")     // key: "current_epoch" -> u64 BE (optional)
	BAccounts = []byte("accounts") // key: acct(32) -> head(32) || balance(u64 BE) || seq(u64 BE)
	BTxs      = []byte("txs")      // key: txid(32) -> raw protobuf tx bytes
	BRecv     = []byte("recv")     // key: receivable_id(32) -> raw protobuf receivable bytes
)

var (
	ErrNotFound = errors.New("not found")
)

func ensureBuckets(tx *bbolt.Tx) error {
	for _, b := range [][]byte{BMeta, BAccounts, BTxs, BRecv} {
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
