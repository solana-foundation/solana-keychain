// Package fireblocks provides a SolanaSigner backed by the Fireblocks API.
// Signing requests are created as Fireblocks RAW transactions (or sign-only
// PROGRAM_CALL transactions) and polled to completion, returning a signer-bound
// Ed25519 signature over the message bytes.
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

	// UseProgramCall signs transactions with the PROGRAM_CALL operation instead of
	// RAW. It is sent with signOnly: true and useDurableNonce: false, so Fireblocks
	// signs the submitted transaction without broadcasting it and without rewriting
	// the message. The returned signature is verified against the vault public key
	// over the local message bytes before it is used, and the caller broadcasts as
	// in RAW mode. SignMessage always uses RAW, since PROGRAM_CALL only accepts
	// serialized transactions.
	//
	// PROGRAM_CALL accepts legacy and v0 messages only, requires a hot wallet, and
	// must be enabled for the workspace by Fireblocks.
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
