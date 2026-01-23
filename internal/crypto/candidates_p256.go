package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
)

const (
	candidatesDomainTag   = "ANOSV2/PEER_CANDIDATES/v2"
	finalizationDomainTag = "ANOSV2/EPOCH_FINALIZATION/v1"
)

func CandidatesDigestP256(epoch uint64, validatorID [33]byte, listHash [32]byte) [32]byte {
	tag := []byte(candidatesDomainTag)
	buf := make([]byte, 0, 2+len(tag)+8+33+32)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(tag)))
	buf = append(buf, u16[:]...)
	buf = append(buf, tag...)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], epoch)
	buf = append(buf, u64[:]...)

	buf = append(buf, validatorID[:]...)
	buf = append(buf, listHash[:]...)

	return sha256.Sum256(buf)
}

func VerifyCandidatesSigP256(pub *ecdsa.PublicKey, digest [32]byte, sigDER []byte) bool {
	if pub == nil || len(sigDER) == 0 {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest[:], sigDER)
}

func FinalizationDigestP256(epoch uint64, acceptedTxidsHash [32]byte, frontiersRoot [32]byte) [32]byte {
	tag := []byte(finalizationDomainTag)
	buf := make([]byte, 0, 2+len(tag)+8+32+32)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(tag)))
	buf = append(buf, u16[:]...)
	buf = append(buf, tag...)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], epoch)
	buf = append(buf, u64[:]...)

	buf = append(buf, acceptedTxidsHash[:]...)
	buf = append(buf, frontiersRoot[:]...)

	return sha256.Sum256(buf)
}

func VerifyFinalizationSigP256(pub *ecdsa.PublicKey, digest [32]byte, sigDER []byte) bool {
	if pub == nil || len(sigDER) == 0 {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest[:], sigDER)
}
