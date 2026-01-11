package crypto

import (
	"crypto/ecdsa"
	"io"
)

func SignDigestP256DER(priv *ecdsa.PrivateKey, digest32 [32]byte, rng io.Reader) ([]byte, error) {
	return ecdsa.SignASN1(rng, priv, digest32[:])
}
