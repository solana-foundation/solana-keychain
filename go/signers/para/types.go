// Package para provides a SolanaSigner backed by Para's wallet API. Signing
// is delegated to Para's REST sign-raw endpoint (hex-encoded payloads); the
// wallet's Solana address is fetched once at construction.
package para

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// DefaultBaseURL is Para's production API endpoint.
const DefaultBaseURL = "https://api.getpara.com"

// Config configures a Para signer.
type Config struct {
	// APIKey is the Para API secret key. It must start with "sk_".
	APIKey string

	// WalletID is the Para wallet UUID.
	WalletID string

	// APIBaseURL optionally overrides the Para API base URL. It must use HTTPS;
	// trailing slashes are trimmed. Defaults to DefaultBaseURL.
	APIBaseURL string

	// HTTPClientConfig holds request/connect timeouts for the default HTTP
	// client. The zero value uses core defaults (30s request, 5s connect).
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer
	// builds one with core.NewHTTPClient (HTTPS-only). Supplying a client
	// bypasses HTTPS enforcement; the caller owns that security posture.
	HTTPClient *http.Client
}

// walletResponse is the wallet info returned by GET /v1/wallets/{walletId}.
// Address is a pointer so a missing address (wallet still creating) is
// distinguishable from an empty one.
type walletResponse struct {
	ID      string  `json:"id"`
	Address *string `json:"address"`
	Type    string  `json:"type"`
	Status  string  `json:"status"`
}

// signRawRequest is the body for POST /v1/wallets/{walletId}/sign-raw.
// Encoding is always "hex".
type signRawRequest struct {
	Data     string `json:"data"`
	Encoding string `json:"encoding"`
}

// signRawResponse is the response from POST /v1/wallets/{walletId}/sign-raw.
// Signature is a pointer so a missing field is detectable.
type signRawResponse struct {
	Signature *string `json:"signature"`
}
