package privy

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

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// maxResponseBytes caps how much of a Privy response body is read.
const maxResponseBytes = 1 << 20 // 1 MiB

// Signer signs with a Privy wallet via Privy's REST API. All fields are
// immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	appID                        string
	appSecret                    string
	walletID                     string
	apiBaseURL                   string
	client                       *http.Client
	pubkey                       solana.PublicKey
	authorizationContext         *AuthorizationContext
	authorizationRequestExpiryMs *uint64
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Privy signer and fetches the wallet's public key from the Privy
// API, so the returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.AppID == "" || cfg.AppSecret == "" || cfg.WalletID == "" {
		return nil, core.NewSignerError(core.CodeConfigError,
			"missing required configuration fields (AppID, AppSecret, or WalletID)")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}
	baseURL := cfg.APIBaseURL
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "privy api_base_url must use HTTPS")
	}
	s := &Signer{
		appID:                        cfg.AppID,
		appSecret:                    cfg.AppSecret,
		walletID:                     cfg.WalletID,
		apiBaseURL:                   baseURL,
		client:                       client,
		authorizationContext:         cfg.AuthorizationContext,
		authorizationRequestExpiryMs: resolveAuthorizationRequestExpiryMs(cfg),
	}
	pubkey, err := s.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	s.pubkey = pubkey
	return s, nil
}

// Pubkey returns the wallet's public key fetched during New.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "privy.Signer{pubkey: " + s.pubkey.String() + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes with the Privy wallet and verifies the
// returned signature against the wallet's public key before returning it.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs tx via Privy's signTransaction RPC, submitting the
// full wire transaction so wallet policies with transaction conditions apply.
// Policies must allow the signTransaction method.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	unsignedWire, err := tx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction", err)
	}

	request := signTransactionRequest{
		Method:    "signTransaction",
		ChainType: "solana",
		Params: signTransactionParams{
			Transaction: base64.StdEncoding.EncodeToString(unsignedWire),
			Encoding:    "base64",
		},
	}
	body, err := s.postRPC(ctx, request)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	var signResp signTransactionResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse privy signing response", err)
	}
	signedWire, err := base64.StdEncoding.DecodeString(signResp.Data.SignedTransaction)
	if err != nil {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSerializationError,
			"failed to decode signed transaction returned by privy")
	}
	returned, err := solana.TransactionFromBytes(signedWire)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize signed transaction returned by privy", err)
	}

	position, err := core.SigningPosition(returned, s.pubkey)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if position >= len(returned.Signatures) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"privy signature slot missing from returned transaction")
	}
	sig := returned.Signatures[position]
	if !core.VerifyEd25519(s.pubkey, msg, sig) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed: the returned signature does not match the public key")
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

// postRPC sends a wallet RPC request with Privy auth and
// authorization-signature headers and returns the response body on 2xx.
func (s *Signer) postRPC(ctx context.Context, request any) ([]byte, error) {
	url := s.apiBaseURL + "/wallets/" + s.walletID + "/rpc"
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to serialize privy signing request", err)
	}
	authHeaders, err := s.prepareAuthorizationHeaders(http.MethodPost, url, request)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to build privy signing request", err)
	}
	req.Header.Set("Authorization", s.authHeader())
	req.Header.Set("privy-app-id", s.appID)
	req.Header.Set("Content-Type", "application/json")
	if authHeaders.signature != "" {
		req.Header.Set("privy-authorization-signature", authHeaders.signature)
	}
	if authHeaders.requestExpiry != "" {
		req.Header.Set("privy-request-expiry", authHeaders.requestExpiry)
	}
	return s.do(req, "privy signing")
}

// IsAvailable re-fetches the wallet from the Privy API and reports whether it
// still resolves to this signer's public key. All errors are swallowed and
// reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	pubkey, err := s.fetchPublicKey(ctx)
	return err == nil && pubkey == s.pubkey
}

// authHeader returns the HTTP Basic auth header value for the app credentials.
func (s *Signer) authHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(s.appID+":"+s.appSecret))
}

// fetchPublicKey resolves the wallet's Solana address via GET /wallets/{id}.
func (s *Signer) fetchPublicKey(ctx context.Context) (solana.PublicKey, error) {
	url := s.apiBaseURL + "/wallets/" + s.walletID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeHTTPError, "failed to build privy wallet request", err)
	}
	req.Header.Set("Authorization", s.authHeader())
	req.Header.Set("privy-app-id", s.appID)

	body, err := s.do(req, "privy wallet fetch")
	if err != nil {
		return solana.PublicKey{}, err
	}

	var wallet walletResponse
	if err := json.Unmarshal(body, &wallet); err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse privy wallet response", err)
	}

	if wallet.Address == "" {
		return solana.PublicKey{}, core.NewSignerError(core.CodeRemoteAPIError, "missing address in privy wallet response")
	}
	if wallet.ChainType != "solana" {
		return solana.PublicKey{}, core.NewSignerError(core.CodeRemoteAPIError, "expected Solana wallet, got chain_type="+wallet.ChainType)
	}

	// For Solana wallets, the address is the public key.
	pubkey, err := solana.PublicKeyFromBase58(wallet.Address)
	if err != nil {
		return solana.PublicKey{}, core.NewSignerError(core.CodeInvalidPublicKey, "invalid public key from privy API")
	}
	return pubkey, nil
}

// signBytes signs message via POST /wallets/{id}/rpc with method "signMessage",
// sending the bytes base64-encoded and decoding the base64 signature from the
// response, then verifies it locally.
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	request := signMessageRequest{
		Method:    "signMessage",
		ChainType: "solana",
		Params: signMessageParams{
			Message:  base64.StdEncoding.EncodeToString(message),
			Encoding: "base64",
		},
	}
	body, err := s.postRPC(ctx, request)
	if err != nil {
		return solana.Signature{}, err
	}

	var signResp signMessageResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse privy signing response", err)
	}

	raw, err := base64.StdEncoding.DecodeString(signResp.Data.Signature)
	if err != nil {
		return solana.Signature{}, core.NewSignerError(core.CodeSerializationError, "failed to decode base64 signature from privy")
	}
	if len(raw) != core.SignatureLength {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "failed to parse signature")
	}
	var sig solana.Signature
	copy(sig[:], raw)

	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed: the returned signature does not match the public key")
	}
	return sig, nil
}

// do executes the request and returns the response body, mapping transport
// failures to CodeHTTPError and non-2xx statuses to CodeRemoteAPIError whose
// detail carries only the status code ("API error {status}").
func (s *Signer) do(req *http.Request, what string) ([]byte, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		// Preserve an already-classified error (e.g. the HTTPS-only transport's
		// CodeConfigError) instead of reclassifying it as a transport failure.
		var se *core.SignerError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, core.WrapSignerError(core.CodeHTTPError, what+" request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to read "+what+" response", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Only the status code goes into the detail; the response body is
		// deliberately discarded since it may echo request material.
		return nil, core.NewSignerError(core.CodeRemoteAPIError,
			what+" failed: API error "+strconv.Itoa(resp.StatusCode))
	}
	return body, nil
}
