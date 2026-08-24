package fireblocks

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"net/http"
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
	useProgramCall  bool
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Fireblocks signer and initializes it by fetching the vault
// account's Solana address. The returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	signingKey, err := parseSigningKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)

	assetID := cfg.AssetID
	if assetID == "" {
		assetID = DefaultAssetID
	}
	apiBaseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}
	pollInterval, maxPollAttempts, err := core.ResolvePollBounds(
		cfg.PollInterval, DefaultPollInterval, cfg.MaxPollAttempts, DefaultMaxPollAttempts)
	if err != nil {
		return nil, err
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
		useProgramCall:  cfg.UseProgramCall,
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
// remotely with a RAW operation (a sign-only PROGRAM_CALL when
// Config.UseProgramCall is set), the signature is inserted at this signer's
// required-signer position, and the transaction is serialized and classified
// Complete/Partial.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	var signature solana.Signature
	if s.useProgramCall {
		signature, err = s.signProgramCall(ctx, tx, messageBytes)
	} else {
		signature, err = s.signRawBytes(ctx, messageBytes)
	}
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.AttachSignature(tx, s.pubkey, signature)
}

// IsAvailable reports whether the Fireblocks vault account is reachable
// (GET /v1/vault/accounts/{id}). All errors are swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	status, _, err := s.doRequest(ctx, http.MethodGet, "/v1/vault/accounts/"+s.vaultAccountID, "")
	return err == nil && core.IsSuccess(status)
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

	sig, err := s.requestAndPollSignature(ctx, request, false)
	if err != nil {
		return solana.Signature{}, err
	}

	if err := core.VerifySignature(s.pubkey, message, sig); err != nil {
		return solana.Signature{}, err
	}
	return sig, nil
}

// signProgramCall signs tx with a sign-only PROGRAM_CALL operation. Fireblocks
// returns the signature either in signedMessages or as the txHash of the signed
// transaction, so both carriers are accepted and the candidate bytes are
// verified against the signer's pubkey over message before being surfaced.
func (s *Signer) signProgramCall(ctx context.Context, tx *solana.Transaction, message []byte) (solana.Signature, error) {
	if tx.Message.GetVersion() == solana.MessageVersionV1 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"fireblocks PROGRAM_CALL accepts legacy and v0 messages only; a v1 message cannot be signed in this mode")
	}

	encoded, err := core.Serialize(tx)
	if err != nil {
		return solana.Signature{}, err
	}

	request := createTransactionRequest{
		AssetID:   s.assetID,
		Operation: operationProgramCall,
		Source:    transactionSource{Type: sourceVaultAccount, ID: s.vaultAccountID},
		ExtraParameters: programCallExtraParameters{
			ProgramCallData: encoded,
			SignOnly:        true,
			UseDurableNonce: false,
		},
	}

	sig, err := s.requestAndPollSignature(ctx, request, true)
	if err != nil {
		return solana.Signature{}, err
	}

	if !core.VerifyEd25519(s.pubkey, message, sig) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed - the signature returned for the PROGRAM_CALL does not match the vault public key over the submitted message")
	}
	return sig, nil
}

// requestAndPollSignature creates a signing request and polls it to completion.
func (s *Signer) requestAndPollSignature(ctx context.Context, request createTransactionRequest, programCall bool) (solana.Signature, error) {
	created, err := s.createTransaction(ctx, request)
	if err != nil {
		return solana.Signature{}, err
	}
	response, err := s.pollForSignature(ctx, created.ID, programCall)
	if err != nil {
		return solana.Signature{}, err
	}
	return extractSignature(response, programCall)
}

// extractSignature pulls the signer-bound signature out of a completed
// transaction response: the hex fullSig, or the base58 txHash when the response
// carries no signedMessages for a sign-only PROGRAM_CALL.
func extractSignature(response transactionResponse, allowTxHashCarrier bool) (solana.Signature, error) {
	if len(response.SignedMessages) > 0 {
		return core.DecodeSignatureHex(response.SignedMessages[0].Signature.FullSig, "fireblocks")
	}

	if allowTxHashCarrier && response.TxHash != "" {
		sig, err := solana.SignatureFromBase58(response.TxHash)
		if err != nil {
			return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to decode base58 signature", err)
		}
		return sig, nil
	}

	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"no reusable signature found in response (no signed_messages)")
}
