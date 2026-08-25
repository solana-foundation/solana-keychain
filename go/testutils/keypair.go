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
	return PubkeyOf(TestPrivateKey())
}

// PubkeyOf extracts the Solana public key from an Ed25519 private key.
func PubkeyOf(priv ed25519.PrivateKey) solana.PublicKey {
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return pub
}

// SignWith signs message with priv and returns the Solana signature.
func SignWith(priv ed25519.PrivateKey, message []byte) solana.Signature {
	var sig solana.Signature
	copy(sig[:], ed25519.Sign(priv, message))
	return sig
}

// KeyFromSeed returns a deterministic throwaway Ed25519 keypair derived from a
// single repeated seed byte (used for fixed addresses and mismatch cases).
func KeyFromSeed(seedByte byte) (ed25519.PrivateKey, solana.PublicKey) {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, PubkeyOf(priv)
}
