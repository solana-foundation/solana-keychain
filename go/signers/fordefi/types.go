// Package fordefi provides a SolanaSigner backed by the Fordefi MPC custody
// API. Transaction signing is asynchronous: a signing request is submitted via
// POST, then polled via GET until the MPC signing completes. Every POST carries
// an ECDSA P-256 request-level signature in the x-signature header, separate
// from the Ed25519 signature Fordefi's MPC produces.
package fordefi

import (
	"net/http"
	"time"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Defaults applied when the corresponding Config fields are zero.
const (
	// DefaultAPIBaseURL is the production Fordefi API endpoint.
	DefaultAPIBaseURL = "https://api.fordefi.com"
	// DefaultPollInterval is the delay between transaction status polls.
	DefaultPollInterval = 2 * time.Second
	// DefaultMaxPollAttempts bounds how many status polls run before timing out.
	DefaultMaxPollAttempts = 50
)

// Chain selects Fordefi's native Solana signing mode. When set, transactions
// are submitted as solana_transaction requests (Fordefi may replace the
// blockhash and fees, signs, and auto-broadcasts) and messages as
// solana_message requests. When empty, the signer uses black-box raw signing.
type Chain string

// The Solana chains supported by Fordefi's native signing mode.
const (
	ChainSolanaDevnet  Chain = "solana_devnet"
	ChainSolanaMainnet Chain = "solana_mainnet"
)

// PriorityLevel is a named priority-fee tier for native Solana transactions.
type PriorityLevel string

// The priority-fee tiers Fordefi accepts.
const (
	PriorityLow    PriorityLevel = "low"
	PriorityMedium PriorityLevel = "medium"
	PriorityHigh   PriorityLevel = "high"
)

// Fee type discriminators for native Solana transactions.
const (
	FeeTypePriority = "priority"
	FeeTypeCustom   = "custom"
)

// Fee configures fees for native Solana transactions. Set Type to
// FeeTypePriority with a PriorityLevel, or FeeTypeCustom with UnitPrice and/or
// PriorityFee (lamport string values).
type Fee struct {
	Type          string        `json:"type"`
	PriorityLevel PriorityLevel `json:"priority_level,omitempty"`
	UnitPrice     string        `json:"unit_price,omitempty"`
	PriorityFee   string        `json:"priority_fee,omitempty"`
}

// Config configures a Fordefi signer.
//
// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256 key
// in PrivateKeyPEM, or a custom RequestSigner for KMS/HSM-backed request
// signing.
type Config struct {
	// AccessToken is the Fordefi API bearer token.
	AccessToken string

	// VaultID is the Fordefi vault UUID that holds the Solana key.
	VaultID string

	// PublicKey is the vault's Solana public key (base58). New verifies that it
	// actually belongs to VaultID before returning.
	PublicKey string

	// PrivateKeyPEM is the ECDSA P-256 private key (PKCS#8 or SEC1 PEM) used to
	// sign API requests. Provide exactly one of PrivateKeyPEM or RequestSigner.
	PrivateKeyPEM string

	// RequestSigner is a custom API-request signer (e.g. KMS/HSM-backed).
	// Provide exactly one of PrivateKeyPEM or RequestSigner.
	RequestSigner RequestSigner

	// APIBaseURL overrides the Fordefi API endpoint. Empty means DefaultAPIBaseURL.
	APIBaseURL string

	// PollInterval is the delay between transaction status polls. Zero means
	// DefaultPollInterval.
	PollInterval time.Duration

	// MaxPollAttempts bounds how many status polls run before the signing
	// request times out. Zero means DefaultMaxPollAttempts.
	MaxPollAttempts int

	// Chain, when set, switches from black-box raw signing to Fordefi's native
	// Solana signing mode (see Chain).
	Chain Chain

	// Fee is the native-mode fee configuration. Requires Chain.
	Fee *Fee

	// HTTPClientConfig holds optional HTTP timeouts; the zero value uses the
	// core defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the signer
	// builds one with core.NewHTTPClient(HTTPClientConfig), which enforces
	// HTTPS. Supplying a client bypasses that HTTPS enforcement and the caller
	// owns the resulting security posture.
	HTTPClient *http.Client
}
