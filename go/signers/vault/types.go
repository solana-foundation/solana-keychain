// Package vault provides a SolanaSigner backed by HashiCorp Vault's transit
// secrets engine. The Ed25519 private key never leaves Vault: signing posts the
// payload to the transit sign endpoint and Vault returns the signature.
//
// The transit key must be an Ed25519 key, e.g.:
//
//	vault write transit/keys/my-key type=ed25519
package vault

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Config configures a Vault signer.
type Config struct {
	// VaultAddr is the Vault server address (e.g. "https://vault.example.com").
	VaultAddr string

	// Token is the Vault authentication token, sent as the X-Vault-Token header.
	Token string

	// KeyName is the name of the Ed25519 key in the transit engine.
	KeyName string

	// Pubkey is the base58-encoded Solana public key corresponding to the Vault
	// transit key. Vault's transit API does not return raw Ed25519 public keys in
	// Solana form, so the caller supplies it.
	Pubkey string

	// HTTPClientConfig holds optional HTTP timeouts. The zero value applies the
	// core defaults. Ignored when HTTPClient is set.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client used for Vault requests.
	// When nil, a client is built with core.NewHTTPClient(HTTPClientConfig),
	// which enforces HTTPS. Supplying a client bypasses that HTTPS enforcement —
	// the caller owns the resulting security posture (TLS policy, proxies,
	// timeouts).
	HTTPClient *http.Client
}
