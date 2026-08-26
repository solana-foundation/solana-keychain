package core

import (
	"crypto/ed25519"

	"github.com/solana-foundation/solana-go/v2"
)

// VerifyEd25519 reports whether sig is a valid Ed25519 signature of message by
// pubkey. Remote and KMS backends call this to verify a signature returned by the
// service before surfacing it.
func VerifyEd25519(pubkey solana.PublicKey, message []byte, sig solana.Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pubkey.Bytes()), message, sig[:])
}
