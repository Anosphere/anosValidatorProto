package core

import (
	"bytes"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"anos/internal/crypto"
	pb "anos/internal/proto"
)

var (
	ErrBadSig          = errors.New("bad signature")
	ErrBadPrev         = errors.New("bad prev (must match snapshot head)")
	ErrBadSeq          = errors.New("bad seq")
	ErrInsufficientBal = errors.New("insufficient balance")
	ErrUnknownRecv     = errors.New("unknown receivable_id")
	ErrWrongType       = errors.New("wrong tx type")
)

// Snapshot is the epoch-start view of account states and receivables.
type Snapshot struct {
	Accounts    map[[32]byte]AccountSnap
	Receivables map[[32]byte]struct{} // receivable ids present at epoch start
}

type AccountSnap struct {
	Head    [32]byte
	Balance uint64
	Seq     uint64
}

func ParseTx(raw []byte) (*pb.Tx, error) {
	var tx pb.Tx
	if err := proto.Unmarshal(raw, &tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

// ValidateTxAgainstSnapshot verifies signature and semantic validity against epoch-start snapshot.
// Returns computed txid.
func ValidateTxAgainstSnapshot(tx *pb.Tx, snap *Snapshot) ([32]byte, error) {
	if err := crypto.VerifyTxSignature(tx); err != nil {
		return [32]byte{}, ErrBadSig
	}
	txid, err := crypto.TxID(tx)
	if err != nil {
		return [32]byte{}, ErrBadSig
	}
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return [32]byte{}, errors.New("bad account length")
	}
	var acct [32]byte
	copy(acct[:], tx.Account.V)

	// snapshot view
	as, ok := snap.Accounts[acct]
	if !ok {
		as = AccountSnap{} // zero head/balance/seq
	}

	// prev: nil/empty treated as zeros
	var prev [32]byte
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev[:], tx.Prev.V)
	}
	if prev != as.Head {
		return [32]byte{}, ErrBadPrev
	}
	if tx.Seq != as.Seq+1 {
		return [32]byte{}, ErrBadSeq
	}

	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb, ok := tx.Body.(*pb.Tx_Send)
		if !ok || sb.Send == nil || sb.Send.To == nil || len(sb.Send.To.V) != 32 {
			return [32]byte{}, ErrWrongType
		}
		amt := sb.Send.Amount
		fee := sb.Send.Fee
		if as.Balance < amt+fee {
			return [32]byte{}, ErrInsufficientBal
		}
		// If client provided receivable_id, it must match derived value
		if sb.Send.ReceivableId != nil && len(sb.Send.ReceivableId.V) == 32 {
			want := crypto.ReceivableIDFromTxID(txid)
			if !bytes.Equal(sb.Send.ReceivableId.V, want[:]) {
				return [32]byte{}, errors.New("receivable_id mismatch")
			}
		}
		return txid, nil

	case pb.TxType_TX_TYPE_RECEIVE:
		rb, ok := tx.Body.(*pb.Tx_Receive)
		if !ok || rb.Receive == nil || rb.Receive.ReceivableId == nil || len(rb.Receive.ReceivableId.V) != 32 {
			return [32]byte{}, ErrWrongType
		}
		var rid [32]byte
		copy(rid[:], rb.Receive.ReceivableId.V)
		if _, ok := snap.Receivables[rid]; !ok {
			return [32]byte{}, ErrUnknownRecv // enforces "no same-epoch receive"
		}
		return txid, nil

	default:
		return [32]byte{}, ErrWrongType
	}
}

// ApplyTx applies a validated tx to DB state.
// It assumes prev/seq correctness was checked against snapshot and updates haven't happened mid-commit.
func ApplyTx(view *bboltTxView, raw []byte, parsed *pb.Tx, txid [32]byte) error {
	if hasTx(view.tx, txid) {
		return nil
	}
	if parsed.Account == nil || len(parsed.Account.V) != 32 {
		return errors.New("bad account")
	}
	var acct [32]byte
	copy(acct[:], parsed.Account.V)

	head, bal, seq := getAccount(view.tx, acct)

	// prev compare: nil/empty => zeros
	var prev [32]byte
	if parsed.Prev != nil && len(parsed.Prev.V) == 32 {
		copy(prev[:], parsed.Prev.V)
	}
	if head != prev {
		return fmt.Errorf("apply bad prev: have %x want %x", head[:4], prev[:4])
	}
	if parsed.Seq != seq+1 {
		return fmt.Errorf("apply bad seq: have %d want %d", seq, parsed.Seq-1)
	}

	switch parsed.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb := parsed.GetSend()
		if sb == nil || sb.To == nil || len(sb.To.V) != 32 {
			return ErrWrongType
		}
		amt := sb.Amount
		fee := sb.Fee
		if bal < amt+fee {
			return ErrInsufficientBal
		}
		bal -= (amt + fee)

		// create receivable
		rid := crypto.ReceivableIDFromTxID(txid)
		// If client provided receivable_id, it must match
		if sb.ReceivableId != nil && len(sb.ReceivableId.V) == 32 && !bytes.Equal(sb.ReceivableId.V, rid[:]) {
			return errors.New("receivable_id mismatch")
		}

		var toAcct [32]byte
		copy(toAcct[:], sb.To.V)
		rec := &pb.Receivable{
			Id:          &pb.Hash32{V: rid[:]},
			From:        &pb.AccountId{V: acct[:]},
			To:          &pb.AccountId{V: toAcct[:]},
			Amount:      amt,
			Fee:         fee,
			CreatedByTx: &pb.Hash32{V: txid[:]},
			Claimed:     false,
		}
		rr, _ := proto.Marshal(rec)
		if err := putReceivableRaw(view.tx, rid, rr); err != nil {
			return err
		}

		seq = parsed.Seq
		head = txid
		if err := putAccount(view.tx, acct, head, bal, seq); err != nil {
			return err
		}
		return putTxRaw(view.tx, txid, raw)

	case pb.TxType_TX_TYPE_RECEIVE:
		rb := parsed.GetReceive()
		if rb == nil || rb.ReceivableId == nil || len(rb.ReceivableId.V) != 32 {
			return ErrWrongType
		}
		var rid [32]byte
		copy(rid[:], rb.ReceivableId.V)

		rr, err := getReceivableRaw(view.tx, rid)
		if err != nil {
			return ErrUnknownRecv
		}
		var rec pb.Receivable
		if err := proto.Unmarshal(rr, &rec); err != nil {
			return err
		}
		if rec.Claimed {
			return errors.New("receivable already claimed")
		}
		if rec.To == nil || rec.To.V == nil || !bytesEq32(rec.To.V, acct) {
			return errors.New("receivable not for this account")
		}

		// mark claimed and credit
		bal += rec.Amount
		rec.Claimed = true
		rec.ClaimedByTx = &pb.Hash32{V: txid[:]}

		nrr, _ := proto.Marshal(&rec)
		if err := putReceivableRaw(view.tx, rid, nrr); err != nil {
			return err
		}

		seq = parsed.Seq
		head = txid
		if err := putAccount(view.tx, acct, head, bal, seq); err != nil {
			return err
		}
		return putTxRaw(view.tx, txid, raw)

	default:
		return ErrWrongType
	}
}

type bboltTxView struct{ tx *bbolt.Tx }
