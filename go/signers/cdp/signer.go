package cdp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/solana-foundation/solana-keychain/go/core"
)

const (
	// defaultBaseURL is the production CDP API endpoint.
	defaultBaseURL = "https://api.cdp.coinbase.com"
	// basePath is the CDP Solana accounts base path.
	basePath = "/platform/v2/solana/accounts"
	// maxResponseBytes caps how much of a CDP response body is read.
	maxResponseBytes = 1 << 20
)

// Signer signs Solana transactions and messages with CDP's managed key
// infrastructure via the CDP REST API. The account address is provided at
// construction time; no remote calls happen until a signing method is invoked.
// All fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	apiKeyID     string
	apiKeySecret string
	walletSecret string
	pubkey       solana.PublicKey
	apiBaseURL   string
	apiHost      string
	client       *http.Client
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a CDP signer from cfg. Construction performs no I/O: key material
// is only validated when the first JWT is built.
func New(cfg Config) (*Signer, error) {
	if cfg.APIKeyID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "api_key_id must not be empty")
	}
	if cfg.APIKeySecret == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "api_key_secret must not be empty")
	}
	if cfg.WalletSecret == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "wallet_secret must not be empty")
	}
	if cfg.Address == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "address must not be empty")
	}

	pubkey, err := solana.PublicKeyFromBase58(cfg.Address)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid Solana address: "+cfg.Address, err)
	}

	baseURL := cfg.APIBaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "cdp api_base_url must use HTTPS")
	}
	apiHost, err := extractHost(baseURL)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}

	return &Signer{
		apiKeyID:     cfg.APIKeyID,
		apiKeySecret: cfg.APIKeySecret,
		walletSecret: cfg.WalletSecret,
		pubkey:       pubkey,
		apiBaseURL:   baseURL,
		apiHost:      apiHost,
		client:       client,
	}, nil
}

// Pubkey returns the CDP-managed account's public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "cdp.Signer{pubkey: " + s.pubkey.String() + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via the CDP signMessage endpoint and
// verifies the returned signature against this signer's public key.
//
// Quirk: the CDP signMessage API takes a UTF-8 string, so non-UTF-8 payloads
// are rejected with CodeSerializationError.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	var sig solana.Signature
	if !utf8.Valid(message) {
		return sig, core.NewSignerError(core.CodeSerializationError,
			"CDP signMessage requires UTF-8; non-UTF-8 bytes are not supported")
	}

	path := basePath + "/" + s.pubkey.String() + "/sign/message"
	var resp signMessageResponse
	if err := s.doPost(ctx, path, map[string]any{"message": string(message)}, &resp, "sign_message"); err != nil {
		return sig, err
	}

	// CDP returns a base58-encoded signature.
	sigBytes, err := base58.Decode(resp.Signature)
	if err != nil {
		return sig, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode base58 signature from CDP", err)
	}
	if len(sigBytes) != core.SignatureLength {
		return sig, core.NewSignerError(core.CodeSigningFailed,
			"invalid signature length from CDP (expected 64 bytes)")
	}
	copy(sig[:], sigBytes)

	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed — the returned signature does not match the public key")
	}
	return sig, nil
}

// SignTransaction sends the full serialized transaction (base64 wire format,
// with required-signature slots zero-filled) to the CDP signTransaction
// endpoint, then extracts only this signer's signature from the returned
// signed transaction, verifies it against the original message bytes, and
// applies it to tx.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize transaction message", err)
	}
	pos, err := core.SigningPosition(tx, s.pubkey)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	// Serialize the full transaction (Solana wire format): the wire encoding
	// carries one slot per required signature, so pad a copy with zero-filled
	// slots.
	reqTx := *tx
	if n := int(tx.Message.Header.NumRequiredSignatures); len(reqTx.Signatures) < n {
		sigs := make([]solana.Signature, n)
		copy(sigs, tx.Signatures)
		reqTx.Signatures = sigs
	}
	serialized, err := reqTx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize transaction", err)
	}

	path := basePath + "/" + s.pubkey.String() + "/sign/transaction"
	body := map[string]any{"transaction": base64.StdEncoding.EncodeToString(serialized)}
	var resp signTransactionResponse
	if err := s.doPost(ctx, path, body, &resp, "sign_transaction"); err != nil {
		return core.SignedTransaction{}, err
	}

	// Decode and deserialize the returned signed transaction.
	signedBytes, err := base64.StdEncoding.DecodeString(resp.SignedTransaction)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode base64 signed transaction from CDP", err)
	}
	signedTx, err := solana.TransactionFromBytes(signedBytes)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize signed transaction from CDP", err)
	}

	// Extract only our signature from the response and apply it to the original
	// transaction.
	if pos >= len(signedTx.Signatures) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature not found at expected position in CDP response")
	}
	sig := signedTx.Signatures[pos]
	if !core.VerifyEd25519(s.pubkey, msgBytes, sig) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed — the returned signature does not match the public key")
	}

	if err := core.AddSignature(tx, s.pubkey, sig); err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(tx)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(tx, encoded, sig), nil
}

// IsAvailable checks that the CDP API is reachable and this account is
// accessible by fetching the account info (GET, bearer auth only). All errors
// are swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	path := basePath + "/" + s.pubkey.String()
	authToken, err := createAuthJWT(s.apiKeyID, s.apiKeySecret, s.apiHost, http.MethodGet, path)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiBaseURL+path, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// doPost sends an authenticated POST to a CDP signing endpoint (bearer auth JWT
// plus X-Wallet-Auth wallet JWT) and decodes the 2xx JSON response into out.
// what names the endpoint in error details ("sign_message" / "sign_transaction").
func (s *Signer) doPost(ctx context.Context, path string, body map[string]any, out any, what string) error {
	bodyBytes, err := marshalCanonicalJSON(body)
	if err != nil {
		return core.WrapSignerError(core.CodeSerializationError, "failed to serialize request body", err)
	}
	authToken, err := createAuthJWT(s.apiKeyID, s.apiKeySecret, s.apiHost, http.MethodPost, path)
	if err != nil {
		return err
	}
	walletToken, err := createWalletJWT(s.walletSecret, s.apiHost, http.MethodPost, path, body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiBaseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return core.WrapSignerError(core.CodeHTTPError, "failed to build CDP request", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wallet-Auth", walletToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return requestError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return core.WrapSignerError(core.CodeHTTPError, "failed to read CDP response", err)
	}

	// Only the status code goes into the error; the response body is never
	// attached.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return core.NewSignerError(core.CodeRemoteAPIError, "CDP API error "+strconv.Itoa(resp.StatusCode))
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return core.WrapSignerError(core.CodeSerializationError, "failed to parse CDP "+what+" response", err)
	}
	return nil
}

// requestError maps a transport-level failure to CodeHTTPError, but propagates a
// *core.SignerError raised inside the client unchanged (e.g. the HTTPS-only
// transport's CodeConfigError) so its code survives to the caller.
func requestError(err error) error {
	var se *core.SignerError
	if errors.As(err, &se) {
		return se
	}
	return core.WrapSignerError(core.CodeHTTPError, "CDP HTTP request failed", err)
}
