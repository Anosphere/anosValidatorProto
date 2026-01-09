package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	pb "anos/internal/proto"
)

var (
	ErrMissingField = errors.New("missing required field")
	ErrBadLength    = errors.New("bad byte length")
)

// Domain tags (ASCII, includes trailing null byte)
var (
	domainTxSignable    = []byte("ANOSv2-TxSignable\x00")
	domainReceivable    = []byte("ANOSv2-Receivable\x00")
	domainFeeReceivable = []byte("ANOSv2-FeeReceivable\x00")
	domainCandidates    = []byte("ANOSv2-Candidates\x00")
)

// Hash32 returns SHA256(b).
func Hash32(b []byte) [32]byte { return sha256.Sum256(b) }

// --------------------
// ACTE v1 signing bytes
// --------------------

// SignBytesACTE constructs the canonical signing preimage for the given Tx, per ACTE v1.
// IMPORTANT (v1): For SEND, the receivable_id portion is treated as 32 zero bytes because
// receivable_id is deterministically derived from txid (which depends on the signature).
func SignBytesACTE(tx *pb.Tx) ([]byte, error) {
	if tx == nil {
		return nil, ErrMissingField
	}
	if tx.Account == nil || len(tx.Account.V) != 32 {
		return nil, ErrBadLength
	}

	var prev32 [32]byte
	if tx.Prev != nil && len(tx.Prev.V) == 32 {
		copy(prev32[:], tx.Prev.V)
	} // else keep zeros

	// type byte
	var tbyte byte
	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		tbyte = 0x01
	case pb.TxType_TX_TYPE_RECEIVE:
		tbyte = 0x02
	default:
		tbyte = 0x00
	}

	// base = tag || type || account || prev || seq
	out := make([]byte, 0, len(domainTxSignable)+1+32+32+8+1+32+8+8+32)
	out = append(out, domainTxSignable...)
	out = append(out, tbyte)
	out = append(out, tx.Account.V...)
	out = append(out, prev32[:]...)

	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], tx.Seq)
	out = append(out, u64[:]...)

	// body tag + body
	switch tx.Type {
	case pb.TxType_TX_TYPE_SEND:
		sb, ok := tx.Body.(*pb.Tx_Send)
		if !ok || sb.Send == nil || sb.Send.To == nil || len(sb.Send.To.V) != 32 {
			return nil, ErrMissingField
		}
		out = append(out, 0x01) // body_tag SEND
		out = append(out, sb.Send.To.V...)

		binary.LittleEndian.PutUint64(u64[:], sb.Send.Amount)
		out = append(out, u64[:]...)
		binary.LittleEndian.PutUint64(u64[:], sb.Send.Fee)
		out = append(out, u64[:]...)

		// receivable_id is derived from txid => encode as 32 zero bytes for signing/txid
		out = append(out, make([]byte, 32)...)

		return out, nil

	case pb.TxType_TX_TYPE_RECEIVE:
		rb, ok := tx.Body.(*pb.Tx_Receive)
		if !ok || rb.Receive == nil || rb.Receive.ReceivableId == nil || len(rb.Receive.ReceivableId.V) != 32 {
			return nil, ErrMissingField
		}
		out = append(out, 0x02) // body_tag RECEIVE
		out = append(out, rb.Receive.ReceivableId.V...)
		return out, nil

	default:
		// No body
		out = append(out, 0x00)
		return out, nil
	}
}

// MsgHash returns SHA256(SignBytesACTE(tx)) and the sign bytes.
func MsgHash(tx *pb.Tx) ([32]byte, []byte, error) {
	sb, err := SignBytesACTE(tx)
	if err != nil {
		return [32]byte{}, nil, err
	}
	h := sha256.Sum256(sb)
	return h, sb, nil
}

// VerifyTxSignature verifies tx.sig against MsgHash(tx) using account public key.
func VerifyTxSignature(tx *pb.Tx) error {
	if tx == nil || tx.Account == nil || len(tx.Account.V) != 32 {
		return ErrBadLength
	}
	if tx.Sig == nil || len(tx.Sig.V) != 64 {
		return ErrMissingField
	}
	h, _, err := MsgHash(tx)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(tx.Account.V)
	if !ed25519.Verify(pub, h[:], tx.Sig.V) {
		return errors.New("invalid signature")
	}
	return nil
}

// TxID computes txid = SHA256(sign_bytes || sig) per protocol.
func TxID(tx *pb.Tx) ([32]byte, error) {
	if tx == nil || tx.Sig == nil || len(tx.Sig.V) != 64 {
		return [32]byte{}, ErrMissingField
	}
	_, sb, err := MsgHash(tx)
	if err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, 0, len(sb)+64)
	buf = append(buf, sb...)
	buf = append(buf, tx.Sig.V...)
	return sha256.Sum256(buf), nil
}

// ReceivableIDFromTxID computes receivable_id = SHA256("ANOSv2-Receivable\0" || txid).
func ReceivableIDFromTxID(txid [32]byte) [32]byte {
	buf := make([]byte, 0, len(domainReceivable)+32)
	buf = append(buf, domainReceivable...)
	buf = append(buf, txid[:]...)
	return sha256.Sum256(buf)
}

// FeeReceivableIDFromTxID computes fee_receivable_id = SHA256("ANOSv2-FeeReceivable\0" || txid).
func FeeReceivableIDFromTxID(txid [32]byte) [32]byte {
	buf := make([]byte, 0, len(domainFeeReceivable)+32)
	buf = append(buf, domainFeeReceivable...)
	buf = append(buf, txid[:]...)
	return sha256.Sum256(buf)
}

// --------------------
// Candidate list hashing/signing
// --------------------

// CandidatesListHash returns SHA256(concat(sorted_txids)).
func CandidatesListHash(sortedTxIDs [][32]byte) [32]byte {
	h := sha256.New()
	for _, id := range sortedTxIDs {
		h.Write(id[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CandidatesSignBytes returns bytes to sign: domain || epoch(u64 LE) || validatorID(32) || listHash(32).
func CandidatesSignBytes(epoch uint64, validatorID [32]byte, listHash [32]byte) []byte {
	buf := make([]byte, 0, len(domainCandidates)+8+32+32)
	buf = append(buf, domainCandidates...)
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], epoch)
	buf = append(buf, u64[:]...)
	buf = append(buf, validatorID[:]...)
	buf = append(buf, listHash[:]...)
	return buf
}

// VerifyCandidatesSig verifies candidate list signature.
func VerifyCandidatesSig(pub ed25519.PublicKey, epoch uint64, validatorID [32]byte, listHash [32]byte, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	sb := CandidatesSignBytes(epoch, validatorID, listHash)
	h := Hash32(sb)
	return ed25519.Verify(pub, h[:], sig)
}

// SignCandidates signs candidate list payload.
func SignCandidates(priv ed25519.PrivateKey, epoch uint64, validatorID [32]byte, listHash [32]byte) []byte {
	sb := CandidatesSignBytes(epoch, validatorID, listHash)
	h := Hash32(sb)
	return ed25519.Sign(priv, h[:])
}

// LexSortTxIDs sorts txids lexicographically in-place.
func LexSortTxIDs(ids [][32]byte) {
	sortFn := func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 }
	// local simple insertion sort to avoid importing sort in this package
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && sortFn(j, j-1); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}
