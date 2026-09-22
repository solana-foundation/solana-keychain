package core

import (
	voied25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/solana-foundation/solana-go/v2"
)

// zip215Options matches the runtime's verification rules, which crypto/ed25519 is
// stricter than.
var zip215Options = &voied25519.Options{
	Verify: voied25519.VerifyOptionsZIP_215,
}

// VerifyEd25519 reports whether sig is a valid Ed25519 signature of message by
// pubkey. Remote and KMS backends call this to verify a signature returned by the
// service before surfacing it.
func VerifyEd25519(pubkey solana.PublicKey, message []byte, sig solana.Signature) bool {
	return voied25519.VerifyWithOptions(pubkey[:], message, sig[:], zip215Options)
}
