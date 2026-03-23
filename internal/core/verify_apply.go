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

type Snapshot struct {
	Accounts    map[[32]byte]AccountSnap
	Receivables map[[32]byte]struct{}
	// ArbHead and ArbSeq are the arb chain tip at epoch start.
	// Injected into Accounts[ArbChainID] by buildSnapshot so generic prev/seq checks work.
	ArbHead   [32]byte
	ArbSeq    uint64
	SignerSet *pb.SignerSet // nil if not yet bootstrapped
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

		// Enforce fee schedule (SEND only)
		exp := ExpectedFee(amt)
		if fee != exp {
			return [32]byte{}, errors.New("bad fee")
		}

		if as.Balance < amt+fee {
			return [32]byte{}, ErrInsufficientBal
		}

		// If client provided receivable_id, it must match derived value (recipient receivable)
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

	case pb.TxType_TX_TYPE_ADD_ARBITRATOR, pb.TxType_TX_TYPE_REMOVE_ARBITRATOR:
		return validateArbTxAgainstSnapshot(tx, txid, snap)

	default:
		return [32]byte{}, ErrWrongType
	}
}

// ApplyTx applies a validated tx to DB state.
// It assumes prev/seq correctness was checked against snapshot and updates haven't happened mid-commit.
func ApplyTx(view *bboltTxView, raw []byte, parsed *pb.Tx, txid [32]byte, fundAcct [32]byte) error {
	if parsed.Account == nil || len(parsed.Account.V) != 32 {
		return errors.New("bad account")
	}
	var acct [32]byte
	copy(acct[:], parsed.Account.V)

	var head [32]byte
	var bal uint64
	var seq uint64

	if parsed.Type == pb.TxType_TX_TYPE_ADD_ARBITRATOR || parsed.Type == pb.TxType_TX_TYPE_REMOVE_ARBITRATOR {
		head, seq = getArbChain(view.tx)
	} else {
		head, bal, seq = getAccount(view.tx, acct)
	}

	// If this tx is already the current tip for this chain, treat it as already applied.
	// Do NOT skip merely because the raw tx bytes already exist in BTxs: during resync
	// we can have tx bytes present without the corresponding chain state having advanced.
	if head == txid && seq == parsed.Seq {
		return nil
	}

	// prev compare: nil/empty => zeros
	var prev [32]byte
	if parsed.Prev != nil && len(parsed.Prev.V) == 32 {
		copy(prev[:], parsed.Prev.V)
	}
	if head != prev {
		return fmt.Errorf("%w: have %x want %x", ErrBadPrev, head[:4], prev[:4])
	}
	if parsed.Seq != seq+1 {
		return fmt.Errorf("%w: have %d want %d", ErrBadSeq, seq, parsed.Seq-1)
	}

	switch parsed.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb := parsed.GetSend()
		if sb == nil || sb.To == nil || len(sb.To.V) != 32 {
			return ErrWrongType
		}
		amt := sb.Amount
		fee := sb.Fee

		// Enforce fee schedule (SEND only)
		exp := ExpectedFee(amt)
		if fee != exp {
			return errors.New("bad fee")
		}

		if bal < amt+fee {
			return ErrInsufficientBal
		}
		bal -= (amt + fee)

		// -------------------------
		// Recipient receivable (amount)
		// -------------------------
		rid := crypto.ReceivableIDFromTxID(txid)
		// If client provided receivable_id, it must match (recipient receivable)
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
			Fee:         0, // fee is NOT attached to recipient; fee has its own receivable to Fund
			CreatedByTx: &pb.Hash32{V: txid[:]},
			Claimed:     false,
		}
		rr, _ := proto.Marshal(rec)
		if err := putReceivableRaw(view.tx, rid, rr); err != nil {
			return err
		}

		// -------------------------
		// Fund fee receivable (fee)
		// -------------------------
		feeRid := crypto.FeeReceivableIDFromTxID(txid)

		frec := &pb.Receivable{
			Id:          &pb.Hash32{V: feeRid[:]},
			From:        &pb.AccountId{V: acct[:]},
			To:          &pb.AccountId{V: fundAcct[:]},
			Amount:      fee,
			Fee:         0,
			CreatedByTx: &pb.Hash32{V: txid[:]},
			Claimed:     false,
		}
		frr, _ := proto.Marshal(frec)
		if err := putReceivableRaw(view.tx, feeRid, frr); err != nil {
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

	case pb.TxType_TX_TYPE_ADD_ARBITRATOR, pb.TxType_TX_TYPE_REMOVE_ARBITRATOR:
		return applyArbTx(view.tx, raw, parsed, txid)

	default:
		return ErrWrongType
	}
}

func validateArbTxAgainstSnapshot(tx *pb.Tx, txid [32]byte, snap *Snapshot) ([32]byte, error) {
	var acct [32]byte
	copy(acct[:], tx.Account.V)
	if acct != ArbChainID {
		return [32]byte{}, errors.New("arb tx: account must be ArbChainID")
	}
	ss := snap.SignerSet
	if ss == nil || len(ss.Pubkeys) == 0 {
		return [32]byte{}, errors.New("arb tx: signer set not initialised")
	}
	ms := tx.MultiSig
	if ms == nil {
		return [32]byte{}, errors.New("arb tx: missing multi_sig")
	}
	if err := checkFullQuorum(ms, ss); err != nil {
		return [32]byte{}, err
	}
	switch tx.Type {
	case pb.TxType_TX_TYPE_ADD_ARBITRATOR:
		ab := tx.GetAddArbitrator()
		if ab == nil || ab.Pubkey == nil || len(ab.Pubkey.V) != 32 {
			return [32]byte{}, errors.New("arb tx: missing add pubkey")
		}
		for _, p := range ss.Pubkeys {
			if p != nil && bytes.Equal(p.V, ab.Pubkey.V) {
				return [32]byte{}, errors.New("arb tx: pubkey already in signer set")
			}
		}
	case pb.TxType_TX_TYPE_REMOVE_ARBITRATOR:
		rb := tx.GetRemoveArbitrator()
		if rb == nil || rb.Pubkey == nil || len(rb.Pubkey.V) != 32 {
			return [32]byte{}, errors.New("arb tx: missing remove pubkey")
		}
		found := false
		for _, p := range ss.Pubkeys {
			if p != nil && bytes.Equal(p.V, rb.Pubkey.V) {
				found = true
				break
			}
		}
		if !found {
			return [32]byte{}, errors.New("arb tx: pubkey not in signer set")
		}
		if len(ss.Pubkeys) <= 1 {
			return [32]byte{}, errors.New("arb tx: cannot remove last arbitrator")
		}
	}
	return txid, nil
}

// checkFullQuorum verifies that every current arbitrator has a corresponding entry
// in the MultiSig. Crypto validity of each sig was already checked by VerifyTxSignature.
func checkFullQuorum(ms *pb.MultiSig, ss *pb.SignerSet) error {
	signers := make(map[string]struct{}, len(ms.Pubkeys))
	for _, p := range ms.Pubkeys {
		if p != nil && len(p.V) == 32 {
			signers[string(p.V)] = struct{}{}
		}
	}
	for _, p := range ss.Pubkeys {
		if p == nil || len(p.V) != 32 {
			continue
		}
		if _, ok := signers[string(p.V)]; !ok {
			return fmt.Errorf("arb tx: missing signature from arbitrator %x", p.V[:4])
		}
	}
	return nil
}

func applyArbTx(tx *bbolt.Tx, raw []byte, parsed *pb.Tx, txid [32]byte) error {
	ss, _, err := getSignerSetInTx(tx)
	if err != nil {
		return fmt.Errorf("applyArbTx: cannot read signer set: %w", err)
	}
	newSS, err := deriveNewSignerSet(ss, parsed)
	if err != nil {
		return err
	}
	if err := putArbChain(tx, txid, parsed.Seq); err != nil {
		return err
	}
	if err := putSignerSet(tx, newSS); err != nil {
		return err
	}
	return putTxRaw(tx, txid, raw)
}

func deriveNewSignerSet(current *pb.SignerSet, tx *pb.Tx) (*pb.SignerSet, error) {
	existing := make([]*pb.Pub32, 0, len(current.Pubkeys))
	for _, p := range current.Pubkeys {
		if p != nil && len(p.V) == 32 {
			existing = append(existing, &pb.Pub32{V: append([]byte(nil), p.V...)})
		}
	}
	switch tx.Type {
	case pb.TxType_TX_TYPE_ADD_ARBITRATOR:
		ab := tx.GetAddArbitrator()
		if ab == nil || ab.Pubkey == nil {
			return nil, errors.New("deriveNewSignerSet: missing pubkey")
		}
		existing = append(existing, &pb.Pub32{V: append([]byte(nil), ab.Pubkey.V...)})
	case pb.TxType_TX_TYPE_REMOVE_ARBITRATOR:
		rb := tx.GetRemoveArbitrator()
		if rb == nil || rb.Pubkey == nil {
			return nil, errors.New("deriveNewSignerSet: missing pubkey")
		}
		filtered := existing[:0]
		for _, p := range existing {
			if !bytes.Equal(p.V, rb.Pubkey.V) {
				filtered = append(filtered, p)
			}
		}
		existing = filtered
	}
	return &pb.SignerSet{
		Pubkeys:   existing,
		Threshold: uint32(len(existing)), // always full quorum
	}, nil
}

type bboltTxView struct{ tx *bbolt.Tx }
