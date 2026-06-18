// Package memory provides an in-memory Ed25519 SolanaSigner — the Go analog of the
// Rust MemorySigner and the @solana/keychain-memory package. The private key is held
// in process memory; this backend is intended for local development and testing.
package memory

import "crypto/ed25519"

// Config configures a memory signer. Exactly one source field must be set (parity
// with the Rust MemorySignerConfig and the TS MemorySignerConfig).
type Config struct {
	// PrivateKey is a raw Ed25519 private key: 64 bytes (seed‖pubkey, the Solana CLI
	// layout) or 32 bytes (seed only; the public key is derived).
	PrivateKey ed25519.PrivateKey

	// PrivateKeyString is a base58-encoded 64-byte key, OR a u8-array string such as
	// "[1,2,...,64]" (the Solana CLI keypair-file contents).
	PrivateKeyString string

	// PrivateKeyPath is the path to a Solana CLI keypair JSON file.
	PrivateKeyPath string
}
