// internal/core/p256_kms_signer.go
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"

	"anos/internal/crypto"
)

// KMSSigner implements ValidatorSigner using Google Cloud KMS (Cloud HSM supported).
// It expects an EC_SIGN_P256_SHA256 key version.
// keyVersionName example:
//
//	projects/PROJECT_ID/locations/us-central1/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/1
type KMSSigner struct {
	client         *kms.KeyManagementClient
	keyVersionName string

	pub    *ecdsa.PublicKey
	pubID  [33]byte // SEC1 compressed P-256 pubkey, used as validator identity
	closed bool
}

func NewKMSSigner(ctx context.Context, keyVersionName string) (*KMSSigner, error) {
	if keyVersionName == "" {
		return nil, errors.New("missing KMS key version name")
	}

	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms.NewKeyManagementClient: %w", err)
	}

	// Fetch public key for this key version.
	pkResp, err := c.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyVersionName})
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("GetPublicKey(%q): %w", keyVersionName, err)
	}
	if pkResp == nil || pkResp.Pem == "" {
		_ = c.Close()
		return nil, errors.New("GetPublicKey returned empty PEM")
	}

	pub, err := parseEcdsaPublicKeyFromPEM(pkResp.Pem)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("parse public key PEM: %w", err)
	}

	id := crypto.CompressP256PublicKey(pub)

	return &KMSSigner{
		client:         c,
		keyVersionName: keyVersionName,
		pub:            pub,
		pubID:          id,
	}, nil
}

func (s *KMSSigner) Close() error {
	if s == nil || s.client == nil || s.closed {
		return nil
	}
	s.closed = true
	return s.client.Close()
}

func (s *KMSSigner) PublicKeyCompressed() [33]byte {
	return s.pubID
}

// SignDigest signs a 32-byte digest using Cloud KMS AsymmetricSign.
// For EC_SIGN_P256_SHA256, KMS expects a SHA-256 digest and returns an ASN.1 DER ECDSA signature. :contentReference[oaicite:0]{index=0}
func (s *KMSSigner) SignDigest(digest32 [32]byte) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("kms signer not initialized")
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: s.keyVersionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest32[:],
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := s.client.AsymmetricSign(ctx, req)

	if err != nil {
		return nil, fmt.Errorf("AsymmetricSign: %w", err)
	}
	if resp == nil || len(resp.Signature) == 0 {
		return nil, errors.New("AsymmetricSign returned empty signature")
	}
	// Signature is ASN.1 DER encoded ECDSA signature bytes.
	return resp.Signature, nil
}

func parseEcdsaPublicKeyFromPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("PEM decode failed")
	}

	// KMS public keys are typically PEM-encoded SubjectPublicKeyInfo.
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Some encodings may be PKCS#1/other; keep error explicit.
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return nil, errors.New("public key is not ECDSA")
	}
	return pub, nil
}
