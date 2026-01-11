package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

func LoadP256PrivateKeyFromHex(hexD string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexD))
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("expected 32 bytes")
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(b)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("invalid scalar")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(b)
	return priv, nil
}

func CompressP256PublicKey(pub *ecdsa.PublicKey) [33]byte {
	var out [33]byte
	if pub == nil || pub.X == nil || pub.Y == nil {
		return out
	}
	x := pub.X.Bytes()
	copy(out[33-len(x):], x)
	if pub.Y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	return out
}
