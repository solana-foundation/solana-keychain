// Package dfns provides a SolanaSigner backed by the Dfns Keys API.
//
// Signing requests are authorized via the Dfns User Action Signing flow: the
// signer requests a challenge from `/auth/action/init`, signs it locally with
// the credential private key (Ed25519, ECDSA P-256, or RSA in PEM format),
// exchanges the assertion at `/auth/action` for a user-action token, and
// attaches that token as the `x-dfns-useraction` header on the Keys API call.
package dfns

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// DefaultAPIBaseURL is the production Dfns API endpoint, used when
// Config.APIBaseURL is empty.
const DefaultAPIBaseURL = "https://api.dfns.io"

// Config configures a Dfns signer. AuthToken, CredID, PrivateKeyPEM, and
// WalletID are required.
type Config struct {
	// AuthToken is a Dfns service account token or personal access token, sent
	// as the Authorization bearer token on every request.
	AuthToken string

	// CredID is the credential ID used for user action signing.
	CredID string

	// PrivateKeyPEM is the credential private key in PEM format used to sign
	// user action challenges. Supported kinds: Ed25519
	// (PKCS#8), ECDSA P-256 (PKCS#8 or SEC1), or RSA (PKCS#8).
	PrivateKeyPEM string

	// WalletID is the Dfns wallet ID whose signing key backs this signer.
	WalletID string

	// APIBaseURL overrides the Dfns API base URL. Empty means DefaultAPIBaseURL.
	APIBaseURL string

	// HTTPClientConfig holds optional HTTP timeouts; the zero value uses the
	// core defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client used for all Dfns API
	// calls. When nil, a client is built with core.NewHTTPClient(HTTPClientConfig),
	// which enforces HTTPS. Supplying a client bypasses that HTTPS enforcement
	// and the caller owns that security posture.
	HTTPClient *http.Client
}
