package crossmint

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"

	"github.com/solana-foundation/solana-go/v2/base58"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// signerSecretPrefix is the expected prefix of a Crossmint server signer secret.
const signerSecretPrefix = "xmsk1_"

// hkdfSalt is the fixed HKDF salt used by Crossmint server-signer derivation.
const hkdfSalt = "crossmint"

// deriveSigningKey derives the Ed25519 approval key from a server signer
// secret: the secret's 64 hex chars (after an optional "xmsk1_" prefix) are
// the HKDF-SHA256 IKM, the salt is "crossmint", the info string is
// "{projectId}:{environment}:solana-ed25519" (both extracted from the API
// key), and the 32-byte output is the Ed25519 seed.
func deriveSigningKey(secret, apiKey string) (ed25519.PrivateKey, error) {
	projectID, environment, err := parseAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	rawSecret := strings.TrimPrefix(secret, signerSecretPrefix)
	if len(rawSecret) != 64 {
		return nil, core.NewSignerError(core.CodeConfigError,
			fmt.Sprintf("signer_secret must be a 64-char hex string (got %d)", len(rawSecret)))
	}
	ikm, err := hex.DecodeString(rawSecret)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeConfigError, "signer_secret is not valid hex", err)
	}

	info := projectID + ":" + environment + ":solana-ed25519"
	reader := hkdf.New(sha256.New, ikm, []byte(hkdfSalt), []byte(info))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(reader, seed); err != nil {
		return nil, core.WrapSignerError(core.CodeConfigError, "HKDF expand failed", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// parseAPIKey extracts the projectId and environment from a Crossmint API key.
// Format: {ck|sk}_{environment}_{base58data}, where the base58 data decodes to
// the UTF-8 string "projectId:nacl_signature".
func parseAPIKey(apiKey string) (projectID, environment string, err error) {
	parts := strings.SplitN(apiKey, "_", 3)
	if len(parts) < 3 {
		return "", "", core.NewSignerError(core.CodeConfigError, "invalid API key format")
	}
	environment = parts[1]

	decoded, err := base58.Decode(parts[2])
	if err != nil {
		return "", "", core.WrapSignerError(core.CodeConfigError, "failed to decode API key data", err)
	}
	if !utf8.Valid(decoded) {
		return "", "", core.NewSignerError(core.CodeConfigError, "API key data is not valid UTF-8")
	}
	projectID = strings.SplitN(string(decoded), ":", 2)[0]
	return projectID, environment, nil
}
