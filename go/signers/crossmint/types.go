// Package crossmint provides a SolanaSigner backed by the Crossmint Wallets
// API: transactions are created remotely, polled to completion, and (when a
// server signer secret is configured) automatically approved with an HKDF-derived
// Ed25519 key.
package crossmint

import (
	"net/http"
	"time"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

const (
	// DefaultBaseURL is the production Crossmint API base URL.
	DefaultBaseURL = "https://www.crossmint.com/api"
	// DefaultPollInterval is the delay between transaction status polls.
	DefaultPollInterval = time.Second
	// DefaultMaxPollAttempts bounds the polling loop.
	DefaultMaxPollAttempts = 60
)

// walletsAPIVersion is the pinned Crossmint Wallets API version path segment.
const walletsAPIVersion = "2025-06-09"

// Config configures a Crossmint signer.
type Config struct {
	// APIKey is the Crossmint API key, sent as the X-API-KEY header. Required.
	// Format: {ck|sk}_{environment}_{base58data}; the embedded projectId and
	// environment also feed the SignerSecret key derivation.
	APIKey string

	// WalletLocator identifies the wallet (address or locator string such as
	// "userId:<id>:solana:smart"). Required.
	WalletLocator string

	// SignerSecret is an optional server signer secret (`xmsk1_<64hex>`). When
	// provided, the signer derives an Ed25519 keypair via HKDF-SHA256 and
	// automatically signs any `awaiting-approval` transactions from the
	// Crossmint API.
	//
	// Trust boundary: the approval challenge is the message of the transaction
	// Crossmint will execute, which is not derivable from the one submitted because
	// Crossmint rewrites it to sponsor gas. Setting this delegates to Crossmint the
	// choice of what gets approved. The provider is trusted to execute the
	// approved transaction, which may not match the caller's submitted bytes.
	SignerSecret string

	// Signer is an optional explicit signer locator forwarded on transaction
	// creation. When empty and SignerSecret is set, it defaults to
	// "server:<derived base58 pubkey>".
	Signer string

	// APIBaseURL overrides the Crossmint API base URL. Empty means
	// DefaultBaseURL. Must use HTTPS.
	APIBaseURL string

	// PollInterval is the delay between transaction status polls. Zero means
	// DefaultPollInterval; negative values are rejected.
	PollInterval time.Duration

	// MaxPollAttempts bounds the polling loop. Zero means
	// DefaultMaxPollAttempts; negative values are rejected.
	MaxPollAttempts int

	// HTTPClientConfig holds optional timeouts used when building the default
	// HTTP client. The zero value applies the shared defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the client is
	// built with core.NewHTTPClient(HTTPClientConfig). The APIBaseURL HTTPS
	// requirement applies either way.
	HTTPClient *http.Client
}
