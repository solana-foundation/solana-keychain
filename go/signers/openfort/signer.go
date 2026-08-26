package openfort

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

const (
	// DefaultAPIBaseURL is the production Openfort API endpoint.
	DefaultAPIBaseURL = "https://api.openfort.io"
	accountsPath      = "/v2/accounts"
	backendPath       = "/v2/accounts/backend"
)

// Signer signs Solana transactions and messages with an Openfort backend
// wallet. New resolves the wallet's Solana address up front, so the returned
// signer is ready to use.
//
// A Signer is immutable after New and safe for concurrent use.
type Signer struct {
	secretKey    string
	accountID    string
	walletSecret string
	pubkey       solana.PublicKey
	baseURL      string
	apiHost      string
	client       *http.Client
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds an Openfort signer and fetches the wallet's Solana address from
// GET /v2/accounts/{accountId}.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.SecretKey == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "secret_key must not be empty")
	}
	if cfg.AccountID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "account_id must not be empty")
	}
	if cfg.WalletSecret == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "wallet_secret must not be empty")
	}

	baseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}
	apiHost, err := core.HostFromURL(baseURL)
	if err != nil {
		return nil, err
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)

	s := &Signer{
		secretKey:    cfg.SecretKey,
		accountID:    cfg.AccountID,
		walletSecret: cfg.WalletSecret,
		baseURL:      baseURL,
		apiHost:      apiHost,
		client:       client,
	}
	pubkey, err := s.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	s.pubkey = pubkey
	return s, nil
}

// Pubkey returns the wallet's Solana address resolved during New.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "openfort.Signer{accountID: " + s.accountID + ", pubkey: " + s.pubkey.String() + ", baseURL: " + s.baseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via the Openfort API and verifies the
// returned ed25519 signature against the signer's address.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs the transaction's message bytes via the Openfort API,
// inserts the signature at this signer's required-signer position, and returns
// the encoded transaction and its completeness.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	return core.SignTransactionWith(ctx, tx, s.pubkey, s.signBytes)
}

// IsAvailable re-fetches the account and reports whether its address still
// matches the one resolved during New. All errors are swallowed and reported
// as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	pubkey, err := s.fetchPublicKey(ctx)
	return err == nil && pubkey == s.pubkey
}

// fetchPublicKey calls GET /v2/accounts/{accountId} (bearer auth only, no
// wallet JWT) and parses the Solana address.
func (s *Signer) fetchPublicKey(ctx context.Context) (solana.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+accountsPath+"/"+s.accountID, nil)
	if err != nil {
		return solana.PublicKey{}, core.WrapSignerError(core.CodeHTTPError, "failed to build openfort request", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.secretKey)

	body, err := s.do(req)
	if err != nil {
		return solana.PublicKey{}, err
	}

	var info accountInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return solana.PublicKey{}, core.NewSignerError(core.CodeSerializationError, "failed to parse openfort account response")
	}
	pubkey, err := solana.PublicKeyFromBase58(info.Address)
	if err != nil {
		return solana.PublicKey{}, core.NewSignerError(core.CodeInvalidPublicKey,
			"openfort returned non-Solana address for "+s.accountID+": ensure the account is on an SVM chain")
	}
	return pubkey, nil
}

// callSign sends POST /v2/accounts/backend/{accountId}/sign with hex-encoded
// message bytes. The body bytes sent over the wire are exactly the bytes the
// JWT's reqHash is computed over.
func (s *Signer) callSign(ctx context.Context, message []byte) (signResponse, error) {
	path := backendPath + "/" + s.accountID + "/sign"
	body, err := core.MarshalCanonicalJSON(map[string]any{"data": "0x" + hex.EncodeToString(message)})
	if err != nil {
		return signResponse{}, err
	}
	walletToken, err := createWalletJWT(s.walletSecret, s.apiHost, http.MethodPost, path, body)
	if err != nil {
		return signResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return signResponse{}, core.WrapSignerError(core.CodeHTTPError, "failed to build openfort request", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.secretKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-wallet-auth", walletToken)

	respBody, err := s.do(req)
	if err != nil {
		return signResponse{}, err
	}

	var resp signResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return signResponse{}, core.NewSignerError(core.CodeSerializationError, "failed to parse openfort sign response")
	}
	return resp, nil
}

// signBytes signs message via the Openfort API, decodes the 0x-prefixed hex
// signature, and verifies it against the signer's address.
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	resp, err := s.callSign(ctx, message)
	if err != nil {
		return solana.Signature{}, err
	}

	sig, err := core.DecodeSignatureHex(resp.Signature, "openfort")
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pubkey, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// do executes an Openfort API request and returns the response body of a 2xx
// response. Transport failures map to CodeHTTPError and non-2xx statuses to
// CodeRemoteAPIError whose detail carries the status code and the sanitized
// response body (never rendered by Error()).
func (s *Signer) do(req *http.Request) ([]byte, error) {
	status, body, err := core.SendRequest(s.client, req, "openfort")
	if err != nil {
		return nil, err
	}
	if !core.IsSuccess(status) {
		return nil, core.NewRemoteAPIError("openfort API error", status, body)
	}
	return body, nil
}
