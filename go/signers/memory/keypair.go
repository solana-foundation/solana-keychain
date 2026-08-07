package memory

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// resolvePrivateKey turns a Config into an ed25519.PrivateKey (the 64-byte
// seed‖pubkey form), validating that exactly one source is provided.
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
// For the 64-byte form the public half must match the key derived from the seed;
// inconsistent keypair bytes are rejected.
func privateKeyFromBytes(b []byte) (ed25519.PrivateKey, error) {
	switch len(b) {
	case ed25519.PrivateKeySize: // 64: seed‖pubkey
		key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
		if !bytes.Equal(key[ed25519.SeedSize:], b[ed25519.SeedSize:]) {
			return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
				"public key half does not match the key derived from the seed")
		}
		return key, nil
	case ed25519.SeedSize: // 32: seed only — derive the public half
		return ed25519.NewKeyFromSeed(b), nil
	default:
		return nil, core.NewSignerError(core.CodeInvalidPrivateKey,
			"private key must be 32 (seed) or 64 (seed‖pubkey) bytes")
	}
}

// privateKeyFromString parses a base58 key or a "[1,2,...]" u8-array string. The
// leading "[" disambiguates the two forms.
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

// privateKeyFromFile loads a Solana CLI keypair JSON file. Read failures are
// IO errors; malformed contents are invalid-key errors.
func privateKeyFromFile(path string) (ed25519.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeIOError, "failed to read keypair file", err)
	}
	pk, err := solana.PrivateKeyFromSolanaKeygenFileBytes(contents)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPrivateKey, "failed to parse keypair file", err)
	}
	return privateKeyFromBytes(pk)
}
