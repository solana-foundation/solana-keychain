// Package utila provides a SolanaSigner backed by the Utila API — the Go analog
// of the Rust utila module and the @solana/keychain-utila package. Transactions
// are initiated against an existing Solana wallet in a Utila vault, polled until
// Utila reports them SIGNED, and the wallet's signature is extracted from the
// returned wire transaction and verified locally. Every request is authenticated
// with an RS256 service-account JWT.
package utila

import (
	"net/http"
	"time"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Defaults mirroring the Rust utila module constants.
const (
	// DefaultAPIBaseURL is the production Utila API endpoint (Rust DEFAULT_API_BASE_URL).
	DefaultAPIBaseURL = "https://api.utila.io"
	// DefaultPollInterval is the delay between transaction status polls
	// (Rust DEFAULT_POLL_INTERVAL_MS, TS pollIntervalMs default).
	DefaultPollInterval = time.Second
	// DefaultMaxPollAttempts bounds the polling loop (Rust DEFAULT_MAX_POLL_ATTEMPTS).
	DefaultMaxPollAttempts = 60
)

// utilaAPIAudience is the fixed audience claim of the service-account JWT
// (Rust UTILA_API_AUDIENCE).
const utilaAPIAudience = "https://api.utila.io/"

// tokenTTL is the service-account access token lifetime (Rust TOKEN_TTL_MINUTES).
const tokenTTL = 55 * time.Minute

// availabilityTimeout bounds the wallet fetch performed by IsAvailable
// (Rust AVAILABILITY_TIMEOUT).
const availabilityTimeout = 5 * time.Second

// maxResponseBytes caps how much of a remote response body is read.
const maxResponseBytes = 1 << 20

// Config configures a Utila signer. It mirrors the Rust UtilaSignerConfig and
// the TS UtilaSignerConfig.
type Config struct {
	// ServiceAccountEmail is the Utila service account email, used as the JWT
	// subject and the default designated signer. Required.
	ServiceAccountEmail string

	// ServiceAccountPrivateKeyPEM is the service account's RSA private key in PEM
	// format, used to sign the RS256 access token. Escaped "\n" sequences and
	// carriage returns are normalized before parsing. Required.
	ServiceAccountPrivateKeyPEM string

	// VaultID is the Utila vault holding the wallet; a "vaults/" resource prefix
	// is stripped. Required.
	VaultID string

	// WalletID is the Utila wallet id; a full "vaults/{v}/wallets/{w}" resource
	// name is reduced to the trailing wallet id. Required.
	WalletID string

	// Network is the Utila network resource name, e.g. "networks/solana-devnet".
	// Required.
	Network string

	// APIBaseURL overrides the Utila API endpoint. Empty means DefaultAPIBaseURL.
	// Must use HTTPS.
	APIBaseURL string

	// PollInterval is the delay between transaction status polls. Zero means
	// DefaultPollInterval; negative values are rejected (Go analog of the Rust
	// poll_interval_ms Option, where an explicit 0 is rejected).
	PollInterval time.Duration

	// MaxPollAttempts bounds the polling loop. Zero means DefaultMaxPollAttempts;
	// negative values are rejected.
	MaxPollAttempts int

	// DesignatedSigners are the Utila signer resource names forwarded on
	// transaction initiation. Nil means ["users/{ServiceAccountEmail}"].
	DesignatedSigners []string

	// HTTPClientConfig holds optional timeouts used when building the default
	// HTTP client. The zero value applies the shared defaults.
	HTTPClientConfig core.HTTPClientConfig

	// HTTPClient optionally overrides the HTTP client. When nil, the client is
	// built with core.NewHTTPClient(HTTPClientConfig). The APIBaseURL HTTPS
	// requirement applies either way.
	HTTPClient *http.Client
}

// Wire types for the Utila REST API (Go analogs of the Rust utila/types.rs module).

// walletResponse is the GET wallet payload. Port of the Rust WalletResponse.
type walletResponse struct {
	Wallet *walletData `json:"wallet"`
}

type walletData struct {
	SolanaDetails *solanaDetails `json:"solanaDetails"`
}

type solanaDetails struct {
	Address *string `json:"address"`
}

// initiateTransactionRequest is the transactions:initiate request body. Port of
// the Rust InitiateTransactionRequest (designatedSigners is omitted when empty).
type initiateTransactionRequest struct {
	Details           initiateTransactionDetails `json:"details"`
	DesignatedSigners []string                   `json:"designatedSigners,omitempty"`
}

type initiateTransactionDetails struct {
	SolanaSerializedTransaction solanaSerializedTransaction `json:"solanaSerializedTransaction"`
}

type solanaSerializedTransaction struct {
	Network             string `json:"network"`
	RawTransaction      string `json:"rawTransaction"`
	Publish             bool   `json:"publish"`
	ReplaceBlockhash    bool   `json:"replaceBlockhash"`
	TryReplaceBlockhash bool   `json:"tryReplaceBlockhash"`
}

// transactionEnvelope wraps every Utila transaction payload. Port of the Rust
// TransactionEnvelope.
type transactionEnvelope struct {
	Transaction *utilaTransaction `json:"transaction"`
}

// utilaTransaction is the Utila transaction object. Port of the Rust
// UtilaTransaction.
type utilaTransaction struct {
	Name              string                  `json:"name"`
	State             transactionState        `json:"state"`
	SolanaTransaction *utilaSolanaTransaction `json:"solanaTransaction"`
}

type utilaSolanaTransaction struct {
	RawTransaction *string `json:"rawTransaction"`
}

// transactionState is a Utila transaction lifecycle state. Unrecognized values
// never match SIGNED or a terminal-failure state and so keep the polling loop
// going, matching the Rust #[serde(other)] Unknown fallback.
type transactionState string

// stateSigned is the polling success state.
const stateSigned transactionState = "SIGNED"

// terminalFailureStates mirrors the Rust TransactionState::is_terminal_failure set.
var terminalFailureStates = map[transactionState]struct{}{
	"DECLINED_BY_AML_POLICY": {},
	"MINED_FAILED":           {},
	"FAILED":                 {},
	"DECLINED":               {},
	"REPLACED":               {},
	"CANCELED":               {},
	"DROPPED":                {},
	"EXPIRED":                {},
}

// isTerminalFailure reports whether the state can never progress to SIGNED.
func (s transactionState) isTerminalFailure() bool {
	_, ok := terminalFailureStates[s]
	return ok
}
