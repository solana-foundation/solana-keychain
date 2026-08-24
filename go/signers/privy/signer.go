package privy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

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
	baseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return nil, err
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
	if err := core.VerifySignature(s.pubkey, msg, sig); err != nil {
		return core.SignedTransaction{}, err
	}

	return core.AttachSignature(tx, s.pubkey, sig)
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
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
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

	sig, err := core.DecodeSignatureBase64(signResp.Data.Signature, "privy")
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pubkey, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// do executes the request and returns the response body, mapping transport
// failures to CodeHTTPError and non-2xx statuses to CodeRemoteAPIError whose
// detail carries only the status code ("API error {status}").
func (s *Signer) do(req *http.Request, what string) ([]byte, error) {
	status, body, err := core.SendRequest(s.client, req, "privy")
	if err != nil {
		return nil, err
	}
	if !core.IsSuccess(status) {
		// Only the status code goes into the detail; the response body is
		// deliberately discarded since it may echo request material.
		return nil, core.NewSignerError(core.CodeRemoteAPIError,
			what+" failed: API error "+strconv.Itoa(status))
	}
	return body, nil
}
