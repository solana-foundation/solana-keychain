package dfns

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// getWalletResponse is the subset of the Dfns wallet object the signer needs.
type getWalletResponse struct {
	Status     string     `json:"status"`
	SigningKey signingKey `json:"signingKey"`
}

// signingKey describes the wallet's signing key.
type signingKey struct {
	ID        string `json:"id"`
	Scheme    string `json:"scheme"`
	Curve     string `json:"curve"`
	PublicKey string `json:"publicKey"`
}

// generateSignatureRequest is the Keys API signature request. Kind selects the
// variant: "Message" uses Message; "Transaction" uses Transaction and
// BlockchainKind.
type generateSignatureRequest struct {
	Kind           string `json:"kind"`
	Message        string `json:"message,omitempty"`
	Transaction    string `json:"transaction,omitempty"`
	BlockchainKind string `json:"blockchainKind,omitempty"`
}

// generateSignatureResponse is the Keys API signature response.
type generateSignatureResponse struct {
	Status    string               `json:"status"`
	Signature *signatureComponents `json:"signature"`
}

// signatureComponents holds the hex-encoded r and s halves of the signature.
type signatureComponents struct {
	R string `json:"r"`
	S string `json:"s"`
}

// Signer signs with a Dfns wallet's Ed25519 key via the Dfns Keys API. All
// fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	authToken     string
	credID        string
	privateKeyPEM string
	walletID      string
	keyID         string
	pubkey        solana.PublicKey
	apiBaseURL    string
	client        *http.Client
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Dfns signer and initializes it by fetching the wallet from Dfns.
// It validates that the wallet is Active with an EdDSA/ed25519 signing key and
// resolves the wallet's public key and key ID.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.AuthToken == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "missing required auth token field")
	}
	if cfg.CredID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "missing required credential id field")
	}
	if cfg.PrivateKeyPEM == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "missing required private key pem field")
	}
	if cfg.WalletID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "missing required wallet id field")
	}

	baseURL := cfg.APIBaseURL
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "dfns api_base_url must use HTTPS")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}

	s := &Signer{
		authToken:     cfg.AuthToken,
		credID:        cfg.CredID,
		privateKeyPEM: cfg.PrivateKeyPEM,
		walletID:      cfg.WalletID,
		apiBaseURL:    baseURL,
		client:        client,
	}

	wallet, err := s.getWallet(ctx)
	if err != nil {
		return nil, err
	}
	if wallet.Status != "Active" {
		return nil, core.NewSignerError(core.CodeConfigError, "wallet is not active: "+wallet.Status)
	}
	if wallet.SigningKey.Scheme != "EdDSA" {
		return nil, core.NewSignerError(core.CodeConfigError, "unsupported key scheme: "+wallet.SigningKey.Scheme+" (expected EdDSA)")
	}
	if wallet.SigningKey.Curve != "ed25519" {
		return nil, core.NewSignerError(core.CodeConfigError, "unsupported key curve: "+wallet.SigningKey.Curve+" (expected ed25519)")
	}

	pubkeyBytes, err := hex.DecodeString(wallet.SigningKey.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "failed to decode hex public key", err)
	}
	if len(pubkeyBytes) != solana.PublicKeyLength {
		return nil, core.NewSignerError(core.CodeInvalidPublicKey, "invalid public key length (expected 32 bytes)")
	}
	copy(s.pubkey[:], pubkeyBytes)
	s.keyID = wallet.SigningKey.ID

	return s, nil
}

// getWallet fetches the wallet details from Dfns.
func (s *Signer) getWallet(ctx context.Context) (*getWalletResponse, error) {
	data, err := s.do(ctx, http.MethodGet, "/wallets/"+s.walletID, nil, nil, "dfns API error")
	if err != nil {
		return nil, err
	}
	var wallet getWalletResponse
	if err := json.Unmarshal(data, &wallet); err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to parse wallet response", err)
	}
	return &wallet, nil
}

// sendSignatureRequest performs the user-action flow and posts the signature
// request to the Keys API, returning the combined 64-byte signature.
func (s *Signer) sendSignatureRequest(ctx context.Context, request generateSignatureRequest) (solana.Signature, error) {
	httpPath := "/keys/" + s.keyID + "/signatures"
	bodyJSON, err := marshalJSON(request)
	if err != nil {
		return solana.Signature{}, err
	}

	userAction, err := s.signUserAction(ctx, http.MethodPost, httpPath, string(bodyJSON))
	if err != nil {
		return solana.Signature{}, err
	}

	data, err := s.do(ctx, http.MethodPost, httpPath, bodyJSON,
		map[string]string{"x-dfns-useraction": userAction}, "dfns API error")
	if err != nil {
		return solana.Signature{}, err
	}

	var sigResponse generateSignatureResponse
	if err := json.Unmarshal(data, &sigResponse); err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to parse signature response", err)
	}
	if sigResponse.Status == "Failed" {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "dfns signing failed")
	}
	if sigResponse.Status != "Signed" {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"unexpected signature status: "+sigResponse.Status+" (may require policy approval)")
	}
	if sigResponse.Signature == nil {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "signature components missing from response")
	}
	return combineSignature(sigResponse.Signature.R, sigResponse.Signature.S)
}

// combineSignature concatenates the hex-decoded r and s components into a
// 64-byte Ed25519 signature. Each component must be exactly 32 bytes: a
// misaligned split could never verify anyway, and rejecting it here yields an
// accurate error instead of a downstream verification failure.
func combineSignature(r, s string) (solana.Signature, error) {
	rBytes, err := hex.DecodeString(strings.TrimPrefix(r, "0x"))
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode signature r", err)
	}
	sBytes, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode signature s", err)
	}
	const componentLength = solana.SignatureLength / 2
	if len(rBytes) != componentLength || len(sBytes) != componentLength {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"invalid signature component length (expected 32-byte r and s)")
	}
	var sig solana.Signature
	copy(sig[:], rBytes)
	copy(sig[componentLength:], sBytes)
	return sig, nil
}

// Pubkey returns the Dfns wallet's public key resolved during New.
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "dfns.Signer{pubkey: " + s.pubkey.String() + ", walletID: " + s.walletID + ", keyID: " + s.keyID + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via the Dfns Keys API "Message" kind
// (hex-encoded with a 0x prefix) and verifies the returned signature against
// the wallet public key before returning it.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	request := generateSignatureRequest{
		Kind:    "Message",
		Message: "0x" + hex.EncodeToString(message),
	}
	sig, err := s.sendSignatureRequest(ctx, request)
	if err != nil {
		return solana.Signature{}, err
	}
	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed — the returned signature does not match the public key")
	}
	return sig, nil
}

// SignTransaction sends the full serialized transaction via the Dfns Keys API
// "Transaction" kind (hex-encoded with a 0x prefix, blockchainKind "Solana"),
// verifies the returned signature against the transaction's message bytes,
// then inserts it at this signer's required-signer position.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	txBytes, err := tx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction", err)
	}
	request := generateSignatureRequest{
		Kind:           "Transaction",
		Transaction:    "0x" + hex.EncodeToString(txBytes),
		BlockchainKind: "Solana",
	}
	sig, err := s.sendSignatureRequest(ctx, request)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
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

// IsAvailable reports whether the Dfns wallet is available and healthy:
// reachable, active, and backed by an EdDSA/ed25519 signing key. All errors
// are swallowed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	wallet, err := s.getWallet(ctx)
	if err != nil {
		return false
	}
	return wallet.Status == "Active" &&
		wallet.SigningKey.Scheme == "EdDSA" &&
		wallet.SigningKey.Curve == "ed25519"
}
