package core

import (
	"crypto/ecdsa"
	"crypto/rand"

	"anos/internal/crypto"
)

type LocalP256Signer struct {
	priv *ecdsa.PrivateKey
	pub  [33]byte
}

func NewLocalP256Signer(priv *ecdsa.PrivateKey) *LocalP256Signer {
	return &LocalP256Signer{priv: priv, pub: crypto.CompressP256PublicKey(&priv.PublicKey)}
}

func (s *LocalP256Signer) PublicKeyCompressed() [33]byte { return s.pub }

func (s *LocalP256Signer) SignDigest(digest32 [32]byte) ([]byte, error) {
	return crypto.SignDigestP256DER(s.priv, digest32, rand.Reader)
}
