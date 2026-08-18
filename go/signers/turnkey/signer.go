package turnkey

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Turnkey API paths.
const (
	signRawPayloadPath  = "/public/v1/submit/sign_raw_payload"
	signTransactionPath = "/public/v1/submit/sign_transaction"
	whoAmIPath          = "/public/v1/query/whoami"
)

// Signer signs with an Ed25519 private key held by Turnkey, authenticating each
// request with a P-256 API-key stamp. All fields are immutable after New, so a
// Signer is safe for concurrent use.
type Signer struct {
	organizationID string
	privateKeyID   string
	apiPublicKey   string
	apiPrivateKey  string
	publicKey      solana.PublicKey
	apiBaseURL     string
	client         *http.Client
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Turnkey signer from cfg. Construction is pure: no network I/O.
func New(cfg Config) (*Signer, error) {
	pubkey, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid public key", err)
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
		return nil, core.NewSignerError(core.CodeConfigError, "turnkey api_base_url must use HTTPS")
	}
	return &Signer{
		organizationID: cfg.OrganizationID,
		privateKeyID:   cfg.PrivateKeyID,
		apiPublicKey:   cfg.APIPublicKey,
		apiPrivateKey:  cfg.APIPrivateKey,
		publicKey:      pubkey,
		apiBaseURL:     baseURL,
		client:         client,
	}, nil
}

// Pubkey returns the signer's Solana public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.publicKey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "turnkey.Signer{pubkey: " + s.publicKey.String() + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via the Turnkey sign_raw_payload activity
// and returns the 64-byte Ed25519 signature.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signBytes(ctx, message)
}

// SignTransaction signs tx via the sign_transaction activity, submitting the
// full wire transaction so Turnkey's policy engine can evaluate solana.tx
// conditions. Policies must allow ACTIVITY_TYPE_SIGN_TRANSACTION_V2.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	unsignedWire, err := tx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction", err)
	}

	req := signTransactionRequest{
		Type:           "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
		TimestampMs:    strconv.FormatInt(time.Now().UnixMilli(), 10),
		OrganizationID: s.organizationID,
		Parameters: signTransactionParameters{
			SignWith:            s.privateKeyID,
			Type:                "TRANSACTION_TYPE_SOLANA",
			UnsignedTransaction: hex.EncodeToString(unsignedWire),
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize sign request", err)
	}

	result, err := s.postActivity(ctx, signTransactionPath, body)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if result == nil || result.SignTransactionResult == nil {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed, "invalid response from Turnkey API")
	}

	signedWire, err := hex.DecodeString(result.SignTransactionResult.SignedTransaction)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode signed transaction returned by Turnkey", err)
	}
	returned, err := solana.TransactionFromBytes(signedWire)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize signed transaction returned by Turnkey", err)
	}

	position, err := core.SigningPosition(returned, s.publicKey)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if position >= len(returned.Signatures) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Turnkey signature slot missing from returned transaction")
	}
	sig := returned.Signatures[position]
	if !core.VerifyEd25519(s.publicKey, msg, sig) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed — the returned signature does not match the public key")
	}

	if err := core.AddSignature(tx, s.publicKey, sig); err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(tx)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(tx, encoded, sig), nil
}

// postActivity sends a stamped activity request and returns the result.
// Turnkey populates result only under ACTIVITY_STATUS_COMPLETED; anything
// else (e.g. CONSENSUS_NEEDED under a quorum policy) carries no signature.
func (s *Signer) postActivity(ctx context.Context, path string, body []byte) (*activityResult, error) {
	respBody, err := s.post(ctx, path, body)
	if err != nil {
		return nil, err
	}

	var resp activityResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, core.WrapSignerError(core.CodeSerializationError, "failed to parse sign response", err)
	}
	if resp.Activity.Status != "ACTIVITY_STATUS_COMPLETED" {
		status := resp.Activity.Status
		if status == "" {
			status = "<missing>"
		}
		return nil, core.NewSignerError(core.CodeSigningFailed,
			"Turnkey activity is not completed (status: "+status+")")
	}
	return resp.Activity.Result, nil
}

// IsAvailable reports whether the Turnkey API is reachable and the API
// credentials are valid, via a stamped whoami query. All errors are swallowed
// and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	body, err := json.Marshal(whoAmIRequest{OrganizationID: s.organizationID})
	if err != nil {
		return false
	}
	_, err = s.post(ctx, whoAmIPath, body)
	return err == nil
}

// signBytes signs message via the Turnkey API, assembles the left-padded r/s
// components into a 64-byte signature, and verifies it locally before
// returning.
func (s *Signer) signBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	req := signRequest{
		Type:           "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
		TimestampMs:    strconv.FormatInt(time.Now().UnixMilli(), 10),
		OrganizationID: s.organizationID,
		Parameters: signParameters{
			SignWith:     s.privateKeyID,
			Payload:      hex.EncodeToString(message),
			Encoding:     "PAYLOAD_ENCODING_HEXADECIMAL",
			HashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize sign request", err)
	}

	result, err := s.postActivity(ctx, signRawPayloadPath, body)
	if err != nil {
		return solana.Signature{}, err
	}
	if result == nil || result.SignRawPayloadResult == nil {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "invalid response from Turnkey API")
	}

	sig, err := assembleSignature(result.SignRawPayloadResult.R, result.SignRawPayloadResult.S)
	if err != nil {
		return solana.Signature{}, err
	}
	if !core.VerifyEd25519(s.publicKey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "signature verification failed — the returned signature does not match the public key")
	}
	return sig, nil
}

// assembleSignature decodes the hex r and s components returned by Turnkey and
// concatenates them into a 64-byte Ed25519 signature. Turnkey may return fewer
// than 32 bytes per component, so each is LEFT-padded (right-aligned) to
// exactly 32 bytes before concatenation. Components longer than 32 bytes are
// rejected.
func assembleSignature(rHex, sHex string) (solana.Signature, error) {
	rBytes, err := hex.DecodeString(rHex)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode r", err)
	}
	sBytes, err := hex.DecodeString(sHex)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode s", err)
	}
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed, "invalid signature component length")
	}
	var sig solana.Signature
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// post sends a stamped JSON POST to the Turnkey API and returns the response
// body on 2xx. Non-2xx responses map to RemoteApiError carrying only the
// status code; the response body is deliberately never surfaced (it may echo
// request material).
func (s *Signer) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	stamp, err := s.createStamp(string(body))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiBaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to build request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stamp", stamp)

	resp, err := s.client.Do(req)
	if err != nil {
		// Preserve SignerError codes surfaced by the transport (e.g. the
		// HTTPS-only guard's CodeConfigError).
		var se *core.SignerError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, core.WrapSignerError(core.CodeHTTPError, "request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, core.WrapSignerError(core.CodeHTTPError, "failed to read response body", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, core.NewSignerError(core.CodeRemoteAPIError, "API error "+strconv.Itoa(resp.StatusCode))
	}
	return respBody, nil
}
