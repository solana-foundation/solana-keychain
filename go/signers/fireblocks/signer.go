package fireblocks

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Signer signs with a Solana key held in a Fireblocks vault account. All fields
// are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	apiKey          string
	signingKey      *rsa.PrivateKey
	vaultAccountID  string
	assetID         string
	pubkey          solana.PublicKey
	apiBaseURL      string
	client          *http.Client
	pollInterval    time.Duration
	maxPollAttempts int
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Fireblocks signer and initializes it by fetching the vault
// account's Solana address. The returned signer is ready to use. The unsupported
// Config.UseProgramCall is rejected with CodeConfigError before any network call.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.UseProgramCall {
		return nil, core.NewSignerError(core.CodeConfigError,
			"use_program_call (Fireblocks PROGRAM_CALL signing) is not supported: it broadcasts the transaction on-chain without producing a reusable signer-bound signature, which violates the SolanaSigner contract and risks duplicate spends. Use RAW signing (the default, omit use_program_call) instead.")
	}

	signingKey, err := parseSigningKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}

	assetID := cfg.AssetID
	if assetID == "" {
		assetID = DefaultAssetID
	}
	apiBaseURL := cfg.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = DefaultAPIBaseURL
	}
	if !strings.HasPrefix(apiBaseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "fireblocks api_base_url must use HTTPS")
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	maxPollAttempts := cfg.MaxPollAttempts
	if maxPollAttempts <= 0 {
		maxPollAttempts = DefaultMaxPollAttempts
	}

	s := &Signer{
		apiKey:          cfg.APIKey,
		signingKey:      signingKey,
		vaultAccountID:  cfg.VaultAccountID,
		assetID:         assetID,
		apiBaseURL:      apiBaseURL,
		client:          client,
		pollInterval:    pollInterval,
		maxPollAttempts: maxPollAttempts,
	}

	pubkey, err := s.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	s.pubkey = pubkey
	return s, nil
}

// Pubkey returns the vault account's Solana public key (fetched during New).
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "fireblocks.Signer{pubkey: " + s.pubkey.String() +
		", vaultAccountID: " + s.vaultAccountID + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes with a Fireblocks RAW operation and returns
// the verified 64-byte signature.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	return s.signRawBytes(ctx, message)
}

// SignTransaction signs tx and returns the encoded transaction, this signer's
// signature, and its completeness. The transaction's message bytes are signed
// remotely with a RAW operation, the signature is inserted at this signer's
// required-signer position, and the transaction is serialized and classified
// Complete/Partial.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	signature, err := s.signRawBytes(ctx, messageBytes)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if err := core.AddSignature(tx, s.pubkey, signature); err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(tx)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(tx, encoded, signature), nil
}

// IsAvailable reports whether the Fireblocks vault account is reachable
// (GET /v1/vault/accounts/{id}). All errors are swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	status, _, err := s.doRequest(ctx, http.MethodGet, "/v1/vault/accounts/"+s.vaultAccountID, "")
	return err == nil && is2xx(status)
}

// signRawBytes signs message with a Fireblocks RAW operation: the message bytes
// are hex-encoded into rawMessageData, the request is polled to completion, and
// the returned signature is verified against the signer's pubkey before being
// surfaced.
func (s *Signer) signRawBytes(ctx context.Context, message []byte) (solana.Signature, error) {
	request := createTransactionRequest{
		AssetID:   s.assetID,
		Operation: operationRaw,
		Source:    transactionSource{Type: sourceVaultAccount, ID: s.vaultAccountID},
		ExtraParameters: rawExtraParameters{
			RawMessageData: rawMessageData{
				Messages: []rawMessage{{Content: hex.EncodeToString(message)}},
			},
		},
	}

	sig, err := s.requestAndPollSignature(ctx, request)
	if err != nil {
		return solana.Signature{}, err
	}

	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed - the returned signature does not match the public key")
	}
	return sig, nil
}

// requestAndPollSignature creates a RAW signing request and polls it to
// completion.
func (s *Signer) requestAndPollSignature(ctx context.Context, request createTransactionRequest) (solana.Signature, error) {
	created, err := s.createTransaction(ctx, request)
	if err != nil {
		return solana.Signature{}, err
	}
	response, err := s.pollForSignature(ctx, created.ID)
	if err != nil {
		return solana.Signature{}, err
	}
	return extractSignature(response)
}

// extractSignature pulls the signer-bound signature (hex fullSig) out of a
// completed RAW transaction response.
func extractSignature(response transactionResponse) (solana.Signature, error) {
	if len(response.SignedMessages) > 0 {
		sigBytes, err := hex.DecodeString(response.SignedMessages[0].Signature.FullSig)
		if err != nil {
			return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode hex signature", err)
		}
		if len(sigBytes) != core.SignatureLength {
			return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
				fmt.Sprintf("invalid signature length (expected %d bytes)", core.SignatureLength))
		}
		return solana.SignatureFromBytes(sigBytes), nil
	}

	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"no reusable signature found in response (no signed_messages)")
}
