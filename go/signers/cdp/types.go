// Package cdp provides a SolanaSigner backed by the Coinbase Developer Platform
// (CDP) REST API. Keys are held in CDP's managed key infrastructure; each request
// is authenticated with two per-request JWTs: an `Authorization: Bearer` token
// signed with the CDP API key (EdDSA) and an `X-Wallet-Auth` token signed with
// the wallet secret (ES256) for write endpoints.
package cdp

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Config configures a CDP signer.
type Config struct {
	// APIKeyID is the CDP API key name / ID. It becomes the `kid` header and
	// `sub` claim of the Authorization JWT.
	APIKeyID string

	// APIKeySecret is the CDP API private key: a base64-encoded 64-byte Ed25519
	// key (seed || pubkey). It signs the Authorization bearer JWT (EdDSA).
	APIKeySecret string

	// WalletSecret is the CDP wallet secret: a base64-encoded PKCS#8 DER EC
	// (P-256) private key. It signs the X-Wallet-Auth JWT (ES256) required by
	// the signing endpoints.
	WalletSecret string

	// Address is the Solana account address managed by CDP (base58 pubkey).
	Address string

	// APIBaseURL optionally overrides the CDP API base URL. Defaults to
	// https://api.cdp.coinbase.com.
	APIBaseURL string

	// HTTPClientConfig holds request/connect timeouts for the default HTTP
	// client. The zero value uses core defaults. Ignored when HTTPClient is set.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer
	// builds one with core.NewHTTPClient, which enforces HTTPS. Supplying a
	// client bypasses that HTTPS enforcement and the caller owns that security
	// posture.
	HTTPClient *http.Client
}

// signTransactionResponse is the CDP signTransaction endpoint response body.
type signTransactionResponse struct {
	// SignedTransaction is the base64-encoded signed wire transaction.
	SignedTransaction string `json:"signedTransaction"`
}

// signMessageResponse is the CDP signMessage endpoint response body.
type signMessageResponse struct {
	// Signature is a base58-encoded Ed25519 signature.
	Signature string `json:"signature"`
}
