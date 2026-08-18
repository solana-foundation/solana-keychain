// Package privy provides a SolanaSigner backed by Privy's wallet API. Requests
// authenticate with HTTP Basic auth (app ID + app secret) plus the privy-app-id
// header; message bytes are sent base64-encoded to the wallet RPC endpoint and the
// returned base64 signature is verified locally before use.
package privy

import (
	"net/http"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// DefaultAPIBaseURL is the Privy API base URL used when Config.APIBaseURL is
// empty.
const DefaultAPIBaseURL = "https://api.privy.io/v1"

// Config configures a Privy signer.
type Config struct {
	// AppID is the Privy application ID. Required.
	AppID string

	// AppSecret is the Privy application secret. Required.
	AppSecret string

	// WalletID is the Privy wallet ID. Required.
	WalletID string

	// APIBaseURL overrides the Privy API base URL. Empty means DefaultAPIBaseURL.
	APIBaseURL string

	// HTTPClientConfig holds optional HTTP timeouts; the zero value uses the core
	// defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client (used chiefly for
	// testing). When nil, a client is built with core.NewHTTPClient, which
	// enforces HTTPS. Supplying a client bypasses that HTTPS enforcement; the
	// caller owns that security posture.
	HTTPClient *http.Client

	// AuthorizationContext optionally enables Privy wallet authorization (quorum)
	// signing: every signing request carries a privy-authorization-signature
	// header computed over the canonical request payload. Nil disables it.
	AuthorizationContext *AuthorizationContext

	// AuthorizationRequestExpiryMs is the request-expiry window in milliseconds
	// for authorization signatures. Zero means the 15-minute default
	// (DefaultAuthorizationRequestExpiryMs).
	AuthorizationRequestExpiryMs uint64

	// OmitAuthorizationRequestExpiry omits privy-request-expiry from the signed
	// payload and the request headers.
	OmitAuthorizationRequestExpiry bool
}

// signMessageRequest is the wallet RPC signing request body.
type signMessageRequest struct {
	Method    string            `json:"method"`
	ChainType string            `json:"chain_type"`
	Params    signMessageParams `json:"params"`
}

// signMessageParams carries the base64-encoded message bytes.
type signMessageParams struct {
	Message  string `json:"message"`
	Encoding string `json:"encoding"`
}

// signMessageResponse is the wallet RPC signing response body.
type signMessageResponse struct {
	Method string          `json:"method"`
	Data   signMessageData `json:"data"`
}

// signMessageData carries the base64-encoded signature.
type signMessageData struct {
	Signature string `json:"signature"`
	Encoding  string `json:"encoding"`
}

// signTransactionRequest is the wallet RPC signTransaction request body.
type signTransactionRequest struct {
	Method    string                `json:"method"`
	ChainType string                `json:"chain_type"`
	Params    signTransactionParams `json:"params"`
}

// signTransactionParams carries the base64-encoded wire transaction.
type signTransactionParams struct {
	Transaction string `json:"transaction"`
	Encoding    string `json:"encoding"`
}

// signTransactionResponse is the wallet RPC signTransaction response body.
type signTransactionResponse struct {
	Method string              `json:"method"`
	Data   signTransactionData `json:"data"`
}

// signTransactionData carries the base64-encoded signed wire transaction.
type signTransactionData struct {
	SignedTransaction string `json:"signed_transaction"`
	Encoding          string `json:"encoding"`
}

// walletResponse is the wallet info response; for Solana wallets the address is
// the public key. Only the fields the signer reads are declared; unknown fields
// are ignored.
type walletResponse struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	ChainType string `json:"chain_type"`
}
