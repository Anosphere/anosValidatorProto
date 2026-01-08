package crypto

import "crypto/ed25519"

// ValidatorKeypairFromSeed derives a stable Ed25519 keypair from a 32-byte seed.
func ValidatorKeypairFromSeed(seed []byte) (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)
	return
}
