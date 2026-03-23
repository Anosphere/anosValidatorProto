package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// LoadP256PrivateKeyFromFile reads a private key file at path.
// Supports two formats:
//   - A file containing a raw 32-byte hex string (same as VALIDATOR_ECDSA_PRIV)
//   - A PEM file with a "EC PRIVATE KEY" block (PKCS#8 or SEC1)
func LoadP256PrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		switch block.Type {
		case "EC PRIVATE KEY": // SEC1
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY": // PKCS#8
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("PKCS8 key is not ECDSA")
			}
			return ecKey, nil
		}
	}

	// Fall back to raw hex string
	return LoadP256PrivateKeyFromHex(strings.TrimSpace(string(data)))
}

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
