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
	Receivables map[[32]byte]ReceivableSnap
	// Epoch is the current epoch this snapshot is being validated for; used for transfer
	// unlock timing. Set by the engine after buildSnapshot (identical across validators in
	// a given finalization round).
	Epoch uint64
	// DelayEpochs is the TIMELOCKED_DELAY_EPOCHS consensus parameter (must match across
	// validators). Used to enforce the minimum unlock epoch on transfer creation.
	DelayEpochs uint64
	// AttestorHead and AttestorSeq are the attestor chain tip at epoch start.
	// Injected into Accounts[AttestorChainID] by buildSnapshot so generic prev/seq checks work.
	AttestorHead [32]byte
	AttestorSeq  uint64
	SignerSet    *pb.SignerSet // nil if not yet bootstrapped
}

type AccountSnap struct {
	Head    [32]byte
	Balance uint64
	Seq     uint64
	Class   pb.AccountClass
	// Transfer-chain metadata; only meaningful when Class == ACCOUNT_CLASS_TRANSFER.
	TransferSource [32]byte
	TransferDest   [32]byte
	TransferUnlock uint64
}

// ReceivableSnap is the epoch-start view of an unclaimed receivable, carrying the fields
// validation needs (notably RequiredDestClass for the source-side routing restriction).
type ReceivableSnap struct {
	From              [32]byte
	To                [32]byte
	Amount            uint64
	RequiredDestClass pb.AccountClass
}

// delayForSourceClass returns the timelock delay (in epochs) that a transfer funded by a
// source of the given class must impose. Only TIMELOCKED is implemented in this slice;
// GUARDED/VAULT (their own delays + attestor signature) come in a later slice.
func delayForSourceClass(c pb.AccountClass, timelockedDelay uint64) uint64 {
	switch c {
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED:
		return timelockedDelay
	default:
		return 0
	}
}

// requiredDestClassFor returns the destination-class restriction a receivable must carry,
// based on the SENDER's class. TIMELOCKED/GUARDED/VAULT sends may only fund a TRANSFER
// chain; everything else is unrestricted (UNSPECIFIED).
func requiredDestClassFor(senderClass pb.AccountClass) pb.AccountClass {
	switch senderClass {
	case pb.AccountClass_ACCOUNT_CLASS_TIMELOCKED,
		pb.AccountClass_ACCOUNT_CLASS_GUARDED,
		pb.AccountClass_ACCOUNT_CLASS_VAULT:
		return pb.AccountClass_ACCOUNT_CLASS_TRANSFER
	default:
		return pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED
	}
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

	// Class validation for normal account-chain transactions.
	// Attestor-chain transactions (ADD/REMOVE_ATTESTOR) are excluded.
	if tx.Type == pb.TxType_TX_TYPE_SEND || tx.Type == pb.TxType_TX_TYPE_RECEIVE {
		var txClass pb.AccountClass
		switch tx.Type {
		case pb.TxType_TX_TYPE_SEND:
			sb, _ := tx.Body.(*pb.Tx_Send)
			if sb != nil && sb.Send != nil {
				txClass = sb.Send.AccountClass
			}
		case pb.TxType_TX_TYPE_RECEIVE:
			rb, _ := tx.Body.(*pb.Tx_Receive)
			if rb != nil && rb.Receive != nil {
				txClass = rb.Receive.AccountClass
			}
		}
		if txClass == pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED {
			return [32]byte{}, errors.New("account_class is required for normal account transactions")
		}
		if ok && as.Class != pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED && as.Class != txClass {
			return [32]byte{}, errors.New("account_class mismatch: cannot change class of existing account")
		}
	}

	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb, ok := tx.Body.(*pb.Tx_Send)
		if !ok || sb.Send == nil || sb.Send.To == nil || len(sb.Send.To.V) != 32 {
			return [32]byte{}, ErrWrongType
		}
		amt := sb.Send.Amount
		fee := sb.Send.Fee
		var to [32]byte
		copy(to[:], sb.Send.To.V)

		if as.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Outbound from a transfer chain: zero-fee, all-or-nothing drain. Destination is
			// restricted to the stored source (return, any epoch) or the stored destination
			// (release, only at/after unlock).
			if fee != 0 {
				return [32]byte{}, errors.New("transfer outbound must have zero fee")
			}
			if as.Balance == 0 || amt != as.Balance {
				return [32]byte{}, errors.New("transfer outbound must move the full balance (all-or-nothing)")
			}
			switch {
			case to == as.TransferSource:
				// return to source: allowed at any epoch
			case to == as.TransferDest:
				if snap.Epoch < as.TransferUnlock {
					return [32]byte{}, errors.New("transfer is still locked: release-to-destination not yet allowed")
				}
			default:
				return [32]byte{}, errors.New("transfer outbound must go to the stored source or destination")
			}
		} else {
			// Normal SEND: enforce the fee schedule and balance.
			exp := ExpectedFee(amt)
			if fee != exp {
				return [32]byte{}, errors.New("bad fee")
			}
			if as.Balance < amt+fee {
				return [32]byte{}, ErrInsufficientBal
			}
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
		rs, ok := snap.Receivables[rid]
		if !ok {
			return [32]byte{}, ErrUnknownRecv // enforces "no same-epoch receive"
		}
		recvClass := rb.Receive.AccountClass

		// Single-funding: a transfer chain accepts exactly one RECEIVE (its creation).
		if as.Class == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			return [32]byte{}, errors.New("transfer chain is single-funding: cannot receive again")
		}

		// Source-side routing restriction: a receivable produced by a class-restricted
		// sender (required_dest_class == TRANSFER) may ONLY be claimed by opening a TRANSFER
		// chain. This is what forces timelocked/guarded/vault funds through a transfer.
		if rs.RequiredDestClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER &&
			recvClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			return [32]byte{}, errors.New("receivable requires a TRANSFER-chain destination")
		}

		// Transfer-chain creation rules.
		if recvClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Must be claiming a transfer-restricted receivable (funded by timelocked/guarded/vault).
			if rs.RequiredDestClass != pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
				return [32]byte{}, errors.New("TRANSFER receive must claim a transfer-restricted receivable")
			}
			if rb.Receive.TransferDestination == nil || len(rb.Receive.TransferDestination.V) != 32 {
				return [32]byte{}, errors.New("TRANSFER receive missing transfer_destination")
			}
			// Destination must differ from source: returning to source is always allowed, so a
			// transfer whose destination == source is a degenerate no-op chain. Reject it.
			var dest [32]byte
			copy(dest[:], rb.Receive.TransferDestination.V)
			if dest == rs.From {
				return [32]byte{}, errors.New("TRANSFER destination must differ from source")
			}
			// unlock_epoch must be at least creation_epoch + delay(sourceClass). Using a
			// minimum (>=) rather than exact equality keeps the client robust to which epoch
			// the receive finalizes in, while still guaranteeing at least `delay` epochs of lock.
			srcClass := snap.Accounts[rs.From].Class
			delay := delayForSourceClass(srcClass, snap.DelayEpochs)
			if delay == 0 {
				return [32]byte{}, errors.New("TRANSFER receive: funding account class imposes no transfer delay")
			}
			// Overflow-safe equivalent of: TransferUnlockEpoch < snap.Epoch + delay
			// (avoids a uint64 wrap in the astronomically unlikely event snap.Epoch nears 2^64).
			if rb.Receive.TransferUnlockEpoch < snap.Epoch || rb.Receive.TransferUnlockEpoch-snap.Epoch < delay {
				return [32]byte{}, fmt.Errorf("TRANSFER receive: unlock_epoch %d below minimum (epoch %d + delay %d)",
					rb.Receive.TransferUnlockEpoch, snap.Epoch, delay)
			}
		}
		return txid, nil

	case pb.TxType_TX_TYPE_ADD_ATTESTOR, pb.TxType_TX_TYPE_REMOVE_ATTESTOR:
		return validateAttestorTxAgainstSnapshot(tx, txid, snap)

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
	var existingClass pb.AccountClass
	var arec AccountRecord // full record (carries transfer metadata for TRANSFER accounts)

	if parsed.Type == pb.TxType_TX_TYPE_ADD_ATTESTOR || parsed.Type == pb.TxType_TX_TYPE_REMOVE_ATTESTOR {
		head, seq = getAttestorChain(view.tx)
	} else {
		arec, _ = getAccountRecord(view.tx, acct)
		head, bal, seq, existingClass = arec.Head, arec.Balance, arec.Seq, arec.Class
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

		if existingClass == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			// Outbound from a transfer chain: zero-fee, full-balance drain (all-or-nothing).
			if fee != 0 || bal == 0 || amt != bal {
				return errors.New("transfer outbound must move full balance with zero fee")
			}
			bal = 0
		} else {
			// Enforce fee schedule (SEND only)
			exp := ExpectedFee(amt)
			if fee != exp {
				return errors.New("bad fee")
			}
			if bal < amt+fee {
				return ErrInsufficientBal
			}
			bal -= (amt + fee)
		}

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
			// Source-side routing restriction, DERIVED from the sender's class: forces a
			// timelocked/guarded/vault holder to claim these funds via a TRANSFER chain.
			RequiredDestClass: requiredDestClassFor(existingClass),
		}
		rr, _ := proto.Marshal(rec)
		if err := putReceivableRaw(view.tx, rid, rr); err != nil {
			return err
		}

		// -------------------------
		// Fund fee receivable (only for fee-bearing normal sends; transfer outbound is zero-fee)
		// -------------------------
		if fee > 0 {
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
		}

		seq = parsed.Seq
		head = txid
		// Write the account back, preserving any transfer metadata (read-modify-write).
		arec.Head = head
		arec.Balance = bal
		arec.Seq = seq
		arec.Class = existingClass
		if err := putAccountRecord(view.tx, acct, arec); err != nil {
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

		// Determine class to persist.
		// If the account already has a class, keep it (validation already confirmed tx class matches).
		// If this is a new account (existingClass is UNSPECIFIED), establish class from this tx.
		classToStore := existingClass
		if classToStore == pb.AccountClass_ACCOUNT_CLASS_UNSPECIFIED {
			classToStore = rb.AccountClass
		}

		seq = parsed.Seq
		head = txid

		// Build the account record. For a TRANSFER chain creation, store the immutable
		// transfer metadata directly from committed data: destination & unlock from the
		// signed tx body, source from the funding receivable. Never recomputed (resync-safe).
		out := AccountRecord{Head: head, Balance: bal, Seq: seq, Class: classToStore}
		if classToStore == pb.AccountClass_ACCOUNT_CLASS_TRANSFER {
			if rb.TransferDestination == nil || len(rb.TransferDestination.V) != 32 {
				return errors.New("TRANSFER receive missing transfer_destination")
			}
			if rec.From == nil || len(rec.From.V) != 32 {
				return errors.New("TRANSFER receive: funding receivable has no source")
			}
			copy(out.TransferSource[:], rec.From.V)
			copy(out.TransferDest[:], rb.TransferDestination.V)
			out.TransferUnlock = rb.TransferUnlockEpoch
		}
		if err := putAccountRecord(view.tx, acct, out); err != nil {
			return err
		}
		return putTxRaw(view.tx, txid, raw)

	case pb.TxType_TX_TYPE_ADD_ATTESTOR, pb.TxType_TX_TYPE_REMOVE_ATTESTOR:
		return applyAttestorTx(view.tx, raw, parsed, txid)

	default:
		return ErrWrongType
	}
}

func validateAttestorTxAgainstSnapshot(tx *pb.Tx, txid [32]byte, snap *Snapshot) ([32]byte, error) {
	var acct [32]byte
	copy(acct[:], tx.Account.V)
	if acct != AttestorChainID {
		return [32]byte{}, errors.New("attestor tx: account must be AttestorChainID")
	}
	ss := snap.SignerSet
	if ss == nil || len(ss.Pubkeys) == 0 {
		return [32]byte{}, errors.New("attestor tx: signer set not initialised")
	}
	ms := tx.MultiSig
	if ms == nil {
		return [32]byte{}, errors.New("attestor tx: missing multi_sig")
	}
	if err := checkFullQuorum(ms, ss); err != nil {
		return [32]byte{}, err
	}
	switch tx.Type {
	case pb.TxType_TX_TYPE_ADD_ATTESTOR:
		ab := tx.GetAddAttestor()
		if ab == nil || ab.Pubkey == nil || len(ab.Pubkey.V) != 32 {
			return [32]byte{}, errors.New("attestor tx: missing add pubkey")
		}
		for _, p := range ss.Pubkeys {
			if p != nil && bytes.Equal(p.V, ab.Pubkey.V) {
				return [32]byte{}, errors.New("attestor tx: pubkey already in signer set")
			}
		}
	case pb.TxType_TX_TYPE_REMOVE_ATTESTOR:
		rb := tx.GetRemoveAttestor()
		if rb == nil || rb.Pubkey == nil || len(rb.Pubkey.V) != 32 {
			return [32]byte{}, errors.New("attestor tx: missing remove pubkey")
		}
		found := false
		for _, p := range ss.Pubkeys {
			if p != nil && bytes.Equal(p.V, rb.Pubkey.V) {
				found = true
				break
			}
		}
		if !found {
			return [32]byte{}, errors.New("attestor tx: pubkey not in signer set")
		}
		if len(ss.Pubkeys) <= 1 {
			return [32]byte{}, errors.New("attestor tx: cannot remove last attestor")
		}
	}
	return txid, nil
}

// checkFullQuorum verifies that every current attestor has a corresponding entry
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
			return fmt.Errorf("attestor tx: missing signature from attestor %x", p.V[:4])
		}
	}
	return nil
}

func applyAttestorTx(tx *bbolt.Tx, raw []byte, parsed *pb.Tx, txid [32]byte) error {
	ss, _, err := getSignerSetInTx(tx)
	if err != nil {
		return fmt.Errorf("applyAttestorTx: cannot read signer set: %w", err)
	}
	newSS, err := deriveNewSignerSet(ss, parsed)
	if err != nil {
		return err
	}
	if err := putAttestorChain(tx, txid, parsed.Seq); err != nil {
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
	case pb.TxType_TX_TYPE_ADD_ATTESTOR:
		ab := tx.GetAddAttestor()
		if ab == nil || ab.Pubkey == nil {
			return nil, errors.New("deriveNewSignerSet: missing pubkey")
		}
		existing = append(existing, &pb.Pub32{V: append([]byte(nil), ab.Pubkey.V...)})
	case pb.TxType_TX_TYPE_REMOVE_ATTESTOR:
		rb := tx.GetRemoveAttestor()
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
