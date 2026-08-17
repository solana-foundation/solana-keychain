// Package turnkey provides a SolanaSigner backed by the Turnkey API. Every
// request body is authenticated by stamping it with the P-256 ECDSA API
// private key (X-Stamp header); Ed25519 signatures are produced remotely by
// Turnkey via the sign_raw_payload activity.
package turnkey

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// DefaultAPIBaseURL is the Turnkey API endpoint used when Config.APIBaseURL is
// empty.
const DefaultAPIBaseURL = "https://api.turnkey.com"

// Config configures a Turnkey signer.
type Config struct {
	// APIPublicKey is the Turnkey API public key (hex-encoded compressed P-256
	// point). It is embedded verbatim in every X-Stamp header.
	APIPublicKey string

	// APIPrivateKey is the Turnkey API private key: a hex-encoded 32-byte P-256
	// scalar used to sign request stamps.
	APIPrivateKey string

	// OrganizationID is the Turnkey organization ID.
	OrganizationID string

	// PrivateKeyID is the Turnkey private key ID to sign with.
	PrivateKeyID string

	// PublicKey is the base58-encoded Solana public key corresponding to the
	// Turnkey-held Ed25519 private key.
	PublicKey string

	// APIBaseURL overrides the Turnkey API endpoint. Empty means
	// DefaultAPIBaseURL.
	APIBaseURL string

	// HTTPClientConfig holds optional HTTP timeouts (zero value = defaults).
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer
	// builds one with core.NewHTTPClient(HTTPClientConfig), which enforces
	// HTTPS. Supplying a client bypasses that HTTPS enforcement and the caller
	// owns the resulting security posture.
	HTTPClient *http.Client
}

// Wire types for the Turnkey API (camelCase JSON).

// signRequest is the ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2 request body.
type signRequest struct {
	Type           string         `json:"type"`
	TimestampMs    string         `json:"timestampMs"`
	OrganizationID string         `json:"organizationId"`
	Parameters     signParameters `json:"parameters"`
}

// signParameters are the sign_raw_payload activity parameters.
type signParameters struct {
	SignWith     string `json:"signWith"`
	Payload      string `json:"payload"`
	Encoding     string `json:"encoding"`
	HashFunction string `json:"hashFunction"`
}

// activityResponse is the envelope returned by the submit endpoints.
type activityResponse struct {
	Activity activity `json:"activity"`
}

// activity carries the activity status and (optional) result.
type activity struct {
	Status string          `json:"status"`
	Result *activityResult `json:"result"`
}

// activityResult carries the (optional) raw-payload sign result.
type activityResult struct {
	SignRawPayloadResult *signResult `json:"signRawPayloadResult"`
}

// signResult holds the hex-encoded r and s signature components.
type signResult struct {
	R string `json:"r"`
	S string `json:"s"`
}

// whoAmIRequest is the /public/v1/query/whoami health-check body.
type whoAmIRequest struct {
	OrganizationID string `json:"organizationId"`
}
