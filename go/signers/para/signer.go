package para

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Signer signs Solana transactions and messages via Para's wallet API. All
// fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	apiKey   string
	walletID string
	baseURL  string
	client   *http.Client
	pubkey   solana.PublicKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.TransactionSigner = (*Signer)(nil)

// New builds a Para signer and initializes it by fetching the wallet from
// Para's API and extracting its Solana address.
//
// APIKey must start with "sk_" and WalletID must be a valid UUID. The wallet
// must be of type SOLANA and already have an address; its status is not
// checked here (only IsAvailable checks status).
func New(ctx context.Context, cfg Config) (*Signer, error) {
	s, err := newUninitialized(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.init(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// newUninitialized validates cfg and builds a Signer with a zero public key,
// leaving the wallet fetch to init.
func newUninitialized(cfg Config) (*Signer, error) {
	if cfg.APIKey == "" || cfg.WalletID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "apiKey and walletId must not be empty")
	}
	if !strings.HasPrefix(cfg.APIKey, "sk_") {
		return nil, core.NewSignerError(core.CodeConfigError, "apiKey must be a Para secret key (starts with sk_)")
	}
	if !isValidUUID(cfg.WalletID) {
		return nil, core.NewSignerError(core.CodeConfigError, "walletId must be a valid UUID")
	}
	baseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}
	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)
	return &Signer{
		apiKey:   cfg.APIKey,
		walletID: cfg.WalletID,
		baseURL:  baseURL,
		client:   client,
	}, nil
}

// init fetches the wallet and extracts the public key. A non-ACTIVE/READY
// status is tolerated here; status gates IsAvailable instead.
func (s *Signer) init(ctx context.Context) error {
	wallet, err := s.fetchWallet(ctx)
	if err != nil {
		return err
	}
	if !strings.EqualFold(wallet.Type, "SOLANA") {
		return core.NewSignerError(core.CodeConfigError, "expected SOLANA wallet, got: "+wallet.Type)
	}
	if wallet.Address == nil {
		return core.NewSignerError(core.CodeConfigError, "wallet does not have an address (may still be creating)")
	}
	pubkey, err := solana.PublicKeyFromBase58(*wallet.Address)
	if err != nil {
		return core.NewSignerError(core.CodeInvalidPublicKey, "invalid solana public key from para API")
	}
	s.pubkey = pubkey
	return nil
}

// Pubkey returns the wallet's Solana public key fetched during New.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// SignMessage signs arbitrary bytes via Para's sign-raw endpoint.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes via Para's sign-raw
// endpoint, inserts the signature at this signer's required-signer position,
// and returns the encoded transaction with its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pubkey, s.signBytes)
}

// IsAvailable reports whether the wallet is a SOLANA wallet in ACTIVE or READY
// status. It makes a network call to the Para API bounded by a 5-second
// timeout and swallows all errors; callers should cache the result if
// frequent checks are needed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	wallet, err := s.fetchWallet(ctx)
	if err != nil {
		return false
	}
	return strings.EqualFold(wallet.Type, "SOLANA") &&
		(strings.EqualFold(wallet.Status, "ACTIVE") || strings.EqualFold(wallet.Status, "READY"))
}

// String renders the signer without exposing the API key or wallet ID.
func (s Signer) String() string {
	return "para.Signer{pubkey: " + s.pubkey.String() + "}"
}

// GoString redacts the %#v representation the same way as String.
func (s Signer) GoString() string { return s.String() }

// fetchWallet retrieves wallet info from GET /v1/wallets/{walletId}.
func (s *Signer) fetchWallet(ctx context.Context) (*walletResponse, error) {
	body, err := s.doRequest(ctx, http.MethodGet,
		s.baseURL+"/v1/wallets/"+core.EncodeURIComponent(s.walletID), nil)
	if err != nil {
		return nil, err
	}
	var wallet walletResponse
	if err := json.Unmarshal(body, &wallet); err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to parse para wallet response", err)
	}
	return &wallet, nil
}

// signBytes signs data via POST /v1/wallets/{walletId}/sign-raw with a
// hex-encoded payload, then decodes and verifies the returned signature.
func (s *Signer) signBytes(ctx context.Context, data []byte) (solana.Signature, error) {
	if s.pubkey.IsZero() {
		return solana.Signature{}, core.NewNotInitializedError("para")
	}
	request := signRawRequest{Data: hex.EncodeToString(data), Encoding: "hex"}
	body, err := s.doRequest(ctx, http.MethodPost,
		s.baseURL+"/v1/wallets/"+core.EncodeURIComponent(s.walletID)+"/sign-raw", &request)
	if err != nil {
		return solana.Signature{}, err
	}
	var response signRawResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse para sign-raw response", err)
	}
	if response.Signature == nil {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "missing signature in response")
	}
	sig, err := core.DecodeSignatureHex(*response.Signature, "para")
	if err != nil {
		return solana.Signature{}, err
	}
	if err := core.VerifySignature(s.pubkey, data, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// doRequest performs an authenticated Para API request and returns the raw
// response body. Non-2xx responses map to CodeRemoteAPIError.
func (s *Signer) doRequest(ctx context.Context, method, url string, requestBody any) ([]byte, error) {
	var reader io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return nil, core.WrapSignerError(core.CodeSerializationError, "failed to encode para request body", err)
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to build para request", err)
	}
	req.Header.Set("X-API-Key", s.apiKey)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, body, err := core.SendRequest(s.client, req, "para")
	if err != nil {
		return nil, err
	}
	if !core.IsSuccess(status) {
		return nil, core.NewRemoteAPIError("API error", status, body)
	}
	return body, nil
}

// isValidUUID reports whether s is a UUID in 8-4-4-4-12 form with hex digits.
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// isHexDigit reports whether c is an ASCII hexadecimal digit.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
