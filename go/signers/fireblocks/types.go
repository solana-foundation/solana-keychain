// Package fireblocks provides a SolanaSigner backed by the Fireblocks API.
// Signing requests are created as Fireblocks RAW transactions and polled to
// completion, returning a signer-bound Ed25519 signature over the message bytes.
// Every request is authenticated with a per-request RS256 JWT signed by the RSA
// API secret.
package fireblocks

import (
	"net/http"
	"time"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Defaults applied when the corresponding Config fields are zero.
const (
	// DefaultAPIBaseURL is the production Fireblocks API endpoint.
	DefaultAPIBaseURL = "https://api.fireblocks.io"
	// DefaultAssetID is the mainnet Solana asset id (use "SOL_TEST" for devnet).
	DefaultAssetID = "SOL"
	// DefaultPollInterval is the delay between transaction status polls.
	DefaultPollInterval = time.Second
	// DefaultMaxPollAttempts bounds how many status polls run before timing out.
	DefaultMaxPollAttempts = 300
)

// Config configures a Fireblocks signer.
type Config struct {
	// APIKey is the Fireblocks API key, sent in the X-API-Key header and used as
	// the JWT subject.
	APIKey string

	// PrivateKeyPEM is the RSA API secret in PEM format (PKCS#1 or PKCS#8) used to
	// sign the per-request RS256 JWT.
	PrivateKeyPEM string

	// VaultAccountID is the Fireblocks vault account that holds the Solana key.
	VaultAccountID string

	// AssetID is the Fireblocks asset id. Empty means DefaultAssetID ("SOL"); use
	// "SOL_TEST" for devnet.
	AssetID string

	// APIBaseURL overrides the Fireblocks API endpoint. Empty means DefaultAPIBaseURL.
	APIBaseURL string

	// PollInterval is the delay between transaction status polls. Zero means
	// DefaultPollInterval.
	PollInterval time.Duration

	// MaxPollAttempts bounds how many status polls run before the signing request
	// times out. Zero means DefaultMaxPollAttempts.
	MaxPollAttempts int

	// UseProgramCall is deprecated and unsupported: setting it to true causes New
	// to fail with CodeConfigError before any network call.
	//
	// Fireblocks PROGRAM_CALL signing broadcasts the transaction on-chain and only
	// returns a broadcast transaction id, not a reusable signer-bound signature
	// over the local message bytes. That violates the SolanaSigner contract and
	// risks duplicate spends, so the signer always uses RAW signing (signs message
	// bytes only; the caller broadcasts). Retained so existing callers get a clear
	// error instead of silently different behavior.
	UseProgramCall bool

	// HTTPClientConfig holds optional HTTP timeouts; the zero value uses the
	// core defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer builds
	// one with core.NewHTTPClient(HTTPClientConfig), which enforces HTTPS.
	// Supplying a client bypasses that HTTPS enforcement and the caller owns the
	// resulting security posture.
	HTTPClient *http.Client
}
