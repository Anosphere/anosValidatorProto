package core

type ValidatorSigner interface {
	PublicKeyCompressed() [33]byte
	SignDigest(digest32 [32]byte) ([]byte, error) // DER ECDSA signature
}
