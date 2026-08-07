// Package openfort provides a SolanaSigner backed by an Openfort backend
// wallet.
//
// Signing calls Openfort's POST /v2/accounts/backend/{accountId}/sign
// endpoint; the private key lives in Openfort's TEE and is never exposed.
// Every request carries two headers: "Authorization: Bearer <secret key>"
// (the project secret key) and "x-wallet-auth" (an ES256 JWT signed with the
// project's wallet secret, an ECDSA P-256 private key issued by the Openfort
// dashboard). For SVM wallets Openfort signs the bytes as-is (no hashing) and
// returns a 64-byte ed25519 signature, which the signer verifies against the
// address resolved at construction time.
package openfort

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Config configures an Openfort signer.
type Config struct {
	// SecretKey is the Openfort project secret key (`sk_live_*` or `sk_test_*`).
	SecretKey string

	// AccountID is the backend wallet account ID (`acc_<uuid>`).
	AccountID string

	// WalletSecret is the ECDSA P-256 PKCS#8 private key issued by the
	// Openfort dashboard, used to sign the `x-wallet-auth` JWT. Accepts either
	// the bare base64 DER body (single-line, env-var-friendly) or a full PEM
	// string (`-----BEGIN PRIVATE KEY-----` ...).
	WalletSecret string

	// APIBaseURL overrides the Openfort API base URL. Empty means the default
	// `https://api.openfort.io`.
	APIBaseURL string

	// HTTPClientConfig holds optional HTTP timeouts; the zero value applies the
	// core defaults. Ignored when HTTPClient is set.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer
	// builds one with core.NewHTTPClient (HTTPS-only). Supplying a client
	// bypasses HTTPS enforcement and the caller owns that security posture.
	HTTPClient *http.Client
}

// accountInfo is the subset of GET /v2/accounts/{id} we care about — just the
// on-chain address.
type accountInfo struct {
	Address string `json:"address"`
}

// signResponse is the body of POST /v2/accounts/backend/{id}/sign. Signature
// is hex-encoded with a leading "0x".
type signResponse struct {
	Object    string `json:"object"`
	Account   string `json:"account"`
	Signature string `json:"signature"`
}
