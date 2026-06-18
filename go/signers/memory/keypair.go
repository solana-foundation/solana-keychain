package memory

import (
	"crypto/ed25519"
	"strings"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// resolvePrivateKey turns a Config into an ed25519.PrivateKey (the 64-byte
// seed‖pubkey form), validating that exactly one source is provided. Port of the
// Rust keypair_util.rs parsing and the TS resolveKeyPairSigner source handling.
func resolvePrivateKey(cfg Config) (ed25519.PrivateKey, error) {
	sources := 0
	if len(cfg.PrivateKey) > 0 {
		sources++
	}
	if cfg.PrivateKeyString != "" {
		sources++
	}
	if cfg.PrivateKeyPath != "" {
		sources++
	}
	switch {
	case sources == 0:
		return nil, core.NewSignerError(core.CodeConfigError,
			"memory signer requires one of: PrivateKey, PrivateKeyString, PrivateKeyPath")
	case sources > 1:
		return nil, core.NewSignerError(core.CodeConfigError,
			"memory signer config must have exactly one source")
	case len(cfg.PrivateKey) > 0:
		return privateKeyFromBytes(cfg.PrivateKey)
	case cfg.PrivateKeyString != "":
		return privateKeyFromString(cfg.PrivateKeyString)
	default:
		return privateKeyFromFile(cfg.PrivateKeyPath)
	}
}

// privateKeyFromBytes accepts a 64-byte (seed‖pubkey) or 32-byte (seed) Ed25519 key.
func privateKeyFromBytes(b []byte) (ed25519.PrivateKey, error) {
	switch len(b) {
	case ed25519.PrivateKeySize: // 64: seed‖pubkey
		key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
		copy(key, b)
		return key, nil
	case ed25519.SeedSize: // 32: seed only — derive the public half
		return ed25519.NewKeyFromSeed(b), nil
	default:
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"private key must be 32 (seed) or 64 (seed‖pubkey) bytes")
	}
}

// privateKeyFromString parses a base58 key or a "[1,2,...]" u8-array string. The
// leading "[" disambiguates the two forms, matching the Rust/TS auto-detection.
func privateKeyFromString(s string) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(s)
	var (
		pk  solana.PrivateKey
		err error
	)
	if strings.HasPrefix(trimmed, "[") {
		// Same format as a Solana CLI keypair file's contents.
		pk, err = solana.PrivateKeyFromSolanaKeygenFileBytes([]byte(trimmed))
	} else {
		pk, err = solana.PrivateKeyFromBase58(trimmed)
	}
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey, "failed to parse private key string", err)
	}
	return privateKeyFromBytes(pk)
}

// privateKeyFromFile loads a Solana CLI keypair JSON file.
func privateKeyFromFile(path string) (ed25519.PrivateKey, error) {
	pk, err := solana.PrivateKeyFromSolanaKeygenFile(path)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeIOError, "failed to read keypair file", err)
	}
	return privateKeyFromBytes(pk)
}
