// Package testutils provides shared helpers for testing solana-keychain Go signers:
// deterministic key material and a canonical test-transaction builder. It is a
// regular (non-test) package so it can be imported by _test.go files in any
// backend package.
package testutils

import (
	"crypto/ed25519"

	"github.com/gagliardetto/solana-go"
)

// testSeed is a fixed 32-byte Ed25519 seed so the derived keypair is deterministic
// across runs.
var testSeed = [ed25519.SeedSize]byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

// TestPrivateKey returns the deterministic 64-byte Ed25519 private key (seed‖pubkey).
func TestPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(testSeed[:])
}

// TestPublicKey returns the Solana public key corresponding to TestPrivateKey.
func TestPublicKey() solana.PublicKey {
	return pubkeyFromPriv(TestPrivateKey())
}

// pubkeyFromPriv extracts the Solana public key from an Ed25519 private key.
func pubkeyFromPriv(priv ed25519.PrivateKey) solana.PublicKey {
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return pub
}

// deriveKey returns a deterministic public key from a single seed byte (used for
// fixed, throwaway addresses like a transfer recipient).
func deriveKey(seedByte byte) solana.PublicKey {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	return pubkeyFromPriv(ed25519.NewKeyFromSeed(seed[:]))
}
