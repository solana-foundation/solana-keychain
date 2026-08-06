package crossmint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// awaitingApprovalDetail is the error detail used whenever a transaction is
// stuck awaiting approvals this signer cannot provide (Rust wording).
const awaitingApprovalDetail = "Crossmint transaction is awaiting approval; additional signer approvals are required"

// Signer signs transactions through the Crossmint Wallets API. It is the Go
// analog of the Rust CrossmintSigner and the TS crossmint signer: transactions
// are created remotely, polled to a terminal status, optionally auto-approved
// with the HKDF-derived server signer key, and the wallet's signature is
// extracted from the response and verified locally.
//
// All fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	apiKey        string
	walletLocator string
	// signerLocator is the optional signer forwarded on transaction creation
	// ("" means none); when derived from SignerSecret it is "server:<pubkey>".
	signerLocator   string
	apiBaseURL      string
	client          *http.Client
	publicKey       solana.PublicKey
	pollInterval    time.Duration
	maxPollAttempts int
	// signingKey is the HKDF-derived Ed25519 approval key (nil when no
	// SignerSecret was configured).
	signingKey ed25519.PrivateKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Crossmint signer and resolves the wallet's public key. It is the
// Go analog of Rust's CrossmintSigner::new followed by init() (the same work the
// Signer::from_crossmint factory and the TS createCrossmintSigner factory do),
// so the returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.APIKey == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "api_key must not be empty")
	}
	if cfg.WalletLocator == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "wallet_locator must not be empty")
	}

	apiBaseURL := cfg.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = DefaultBaseURL
	}
	apiBaseURL = strings.TrimRight(apiBaseURL, "/")

	if !strings.HasPrefix(apiBaseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "api_base_url must use HTTPS")
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}
	if pollInterval < 0 {
		return nil, core.NewSignerError(core.CodeConfigError, "poll_interval must be greater than 0")
	}

	maxPollAttempts := cfg.MaxPollAttempts
	if maxPollAttempts == 0 {
		maxPollAttempts = DefaultMaxPollAttempts
	}
	if maxPollAttempts < 0 {
		return nil, core.NewSignerError(core.CodeConfigError, "max_poll_attempts must be greater than 0")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}

	var signingKey ed25519.PrivateKey
	signerLocator := cfg.Signer
	if cfg.SignerSecret != "" {
		key, err := deriveSigningKey(cfg.SignerSecret, cfg.APIKey)
		if err != nil {
			return nil, err
		}
		signingKey = key
		if signerLocator == "" {
			signerLocator = "server:" + base58.Encode(key.Public().(ed25519.PublicKey))
		}
	}

	s := &Signer{
		apiKey:          cfg.APIKey,
		walletLocator:   cfg.WalletLocator,
		signerLocator:   signerLocator,
		apiBaseURL:      apiBaseURL,
		client:          client,
		pollInterval:    pollInterval,
		maxPollAttempts: maxPollAttempts,
		signingKey:      signingKey,
	}

	// Port of the Rust init(): resolve wallet details and the signer pubkey.
	wallet, err := s.fetchWallet(ctx)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(wallet.ChainType, "solana") {
		return nil, core.NewSignerError(core.CodeConfigError, "expected Solana wallet, got chainType="+wallet.ChainType)
	}
	if !strings.EqualFold(wallet.Type, "smart") && !strings.EqualFold(wallet.Type, "mpc") {
		return nil, core.NewSignerError(core.CodeConfigError, "unsupported Crossmint wallet type: "+wallet.Type)
	}
	pub, err := solana.PublicKeyFromBase58(wallet.Address)
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPublicKey, "invalid Solana public key returned by Crossmint wallet")
	}
	s.publicKey = pub

	return s, nil
}

// Pubkey returns the Crossmint wallet's Solana public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.publicKey }

// String renders the signer without any secret material — the Go analog of the
// Rust redacting Debug impl.
func (s *Signer) String() string {
	return "crossmint.Signer{pubkey: " + s.publicKey.String() + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s *Signer) GoString() string { return s.String() }

// SignMessage is intentionally unsupported: Crossmint does not expose raw
// message signing for Solana wallets, so this always fails with
// CodeSigningFailed (parity with the Rust and TS implementations).
func (s *Signer) SignMessage(_ context.Context, _ []byte) (solana.Signature, error) {
	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"Crossmint sign_message is not supported for Solana wallets in this signer")
}

// SignTransaction submits tx to Crossmint, polls it to completion, extracts
// and verifies the wallet's signature, and adds it to tx. Port of the Rust
// sign_and_serialize + sign_transaction.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if s.publicKey.IsZero() {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeConfigError, "signer not initialized")
	}

	expectedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	serialized, err := tx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction", err)
	}

	createResponse, err := s.createTransaction(ctx, base58.Encode(serialized))
	if err != nil {
		return core.SignedTransaction{}, err
	}
	finalResponse, err := s.pollTransaction(ctx, createResponse)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	sig, err := s.extractSignatureFromResponse(finalResponse, expectedMessage)
	if err != nil {
		return core.SignedTransaction{}, err
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

// IsAvailable reports whether the Crossmint wallet can be fetched within the
// availability timeout. Errors are swallowed (parity with the Rust
// check_availability).
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, availabilityTimeout)
	defer cancel()
	_, err := s.fetchWallet(ctx)
	return err == nil
}

// pollTransaction drives a created transaction to a terminal state. Port of
// the Rust poll_transaction: "success" returns, "failed" errors, the first
// "awaiting-approval" triggers a single approval attempt, and anything else
// waits pollInterval and re-fetches, for at most maxPollAttempts iterations
// before the final-status check.
func (s *Signer) pollTransaction(ctx context.Context, response transactionResponse) (transactionResponse, error) {
	approvalSubmitted := false
	for i := 0; i < s.maxPollAttempts; i++ {
		switch {
		case response.Status == "success":
			return response, nil
		case response.Status == "failed":
			return transactionResponse{}, failedTransactionError(response)
		// Submit our approval at most once; Crossmint may register it
		// asynchronously, so afterwards awaiting-approval is treated like any
		// other in-flight status and re-polled.
		case response.Status == "awaiting-approval" && !approvalSubmitted:
			next, err := s.handleAwaitingApproval(ctx, response)
			if err != nil {
				return transactionResponse{}, err
			}
			response = next
			approvalSubmitted = true
		default:
			if err := sleepContext(ctx, s.pollInterval); err != nil {
				return transactionResponse{}, err
			}
			next, err := s.getTransaction(ctx, response.ID)
			if err != nil {
				return transactionResponse{}, err
			}
			response = next
		}
	}

	switch {
	case response.Status == "success":
		return response, nil
	case response.Status == "failed":
		return transactionResponse{}, failedTransactionError(response)
	case response.Status == "awaiting-approval" && !approvalSubmitted:
		return transactionResponse{}, core.NewSignerError(core.CodeSigningFailed, awaitingApprovalDetail)
	default:
		return transactionResponse{}, core.NewSignerError(core.CodeRemoteAPIError,
			fmt.Sprintf("Crossmint transaction polling timed out after %d attempts", s.maxPollAttempts))
	}
}

// failedTransactionError builds the SigningFailed error for a "failed" status,
// carrying the (sanitized) remote error payload like the Rust poll_transaction.
func failedTransactionError(response transactionResponse) error {
	detail := "unknown error"
	if raw := bytes.TrimSpace(response.Error); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil {
			detail = core.SanitizeRemoteResponse(compact.String())
		} else {
			detail = core.SanitizeRemoteResponse(string(raw))
		}
	}
	return core.NewSignerError(core.CodeSigningFailed, "Crossmint transaction failed: "+detail)
}

// handleAwaitingApproval signs the pending approval challenge addressed to
// this signer's locator with the derived server signer key, or fails when no
// key is configured or no matching challenge is pending. Port of the Rust
// handle_awaiting_approval + submit_approval.
func (s *Signer) handleAwaitingApproval(ctx context.Context, response transactionResponse) (transactionResponse, error) {
	if s.signingKey == nil || s.signerLocator == "" {
		return transactionResponse{}, core.NewSignerError(core.CodeSigningFailed, awaitingApprovalDetail)
	}

	// On a multi-approver wallet pending may contain challenges for other
	// approvers; signing one of those with our key yields a vendor 4xx, so
	// only the entry matching our signer locator is ours to approve.
	var pending *pendingApproval
	if response.Approvals != nil {
		for i := range response.Approvals.Pending {
			p := &response.Approvals.Pending[i]
			if p.Signer != nil && p.Signer.Locator != nil && *p.Signer.Locator == s.signerLocator {
				pending = p
				break
			}
		}
	}
	if pending == nil {
		return transactionResponse{}, core.NewSignerError(core.CodeSigningFailed, awaitingApprovalDetail)
	}
	if pending.Message == nil {
		return transactionResponse{}, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint transaction awaiting approval but no pending message found")
	}

	messageBytes, err := base58.Decode(*pending.Message)
	if err != nil {
		return transactionResponse{}, core.WrapSignerError(core.CodeSigningFailed,
			"failed to decode approval message as base58", err)
	}

	signature := ed25519.Sign(s.signingKey, messageBytes)
	return s.submitApprovalRequest(ctx, response.ID, approvalRequest{
		Approvals: []approvalEntry{{
			Signer:    s.signerLocator,
			Signature: base58.Encode(signature),
		}},
	})
}

// extractSignatureFromResponse pulls this wallet's signature out of a terminal
// transaction response. Port of the Rust extract_signature_from_response: the
// serialized onChain.transaction is tried first; onChain.txId is only accepted
// if it verifies against the originally requested message bytes.
func (s *Signer) extractSignatureFromResponse(response transactionResponse, expectedMessage []byte) (solana.Signature, error) {
	if response.OnChain != nil {
		if response.OnChain.Transaction != nil {
			if sig, err := s.extractSignatureFromSerializedTransaction(*response.OnChain.Transaction); err == nil {
				return sig, nil
			}
		}

		if response.OnChain.TxID != nil {
			sig, ok := decodeBase58Signature(*response.OnChain.TxID)
			if !ok {
				return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
					"Crossmint onChain.txId was not a valid Solana signature")
			}
			if err := s.verifySignatureMatchesMessage(sig, expectedMessage); err != nil {
				return solana.Signature{}, err
			}
			return sig, nil
		}
	}

	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"unable to extract signature from Crossmint transaction response")
}

// extractSignatureFromSerializedTransaction decodes the base58 onChain.transaction,
// locates this wallet's required-signer position, and verifies the signature
// against that transaction's own message bytes. Port of the Rust
// extract_signature_from_serialized_transaction.
func (s *Signer) extractSignatureFromSerializedTransaction(serializedTransaction string) (solana.Signature, error) {
	raw, err := base58.Decode(serializedTransaction)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode Crossmint onChain.transaction as base58", err)
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize Crossmint onChain.transaction", err)
	}

	requiredSigners := int(tx.Message.Header.NumRequiredSignatures)
	signerKeys := tx.Message.AccountKeys
	if len(signerKeys) < requiredSigners {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"invalid account index: not enough account keys")
	}

	position := -1
	for i := 0; i < requiredSigners; i++ {
		if signerKeys[i] == s.publicKey {
			position = i
			break
		}
	}
	if position < 0 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"failed to locate signer pubkey in Crossmint transaction")
	}

	if position >= len(tx.Signatures) || tx.Signatures[position].IsZero() {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint onChain.transaction did not contain a signer signature")
	}
	signature := tx.Signatures[position]

	remoteMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Crossmint transaction message", err)
	}
	if err := s.verifySignatureMatchesMessage(signature, remoteMessage); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// verifySignatureMatchesMessage checks a remote signature against this wallet's
// pubkey. Port of the Rust verify_signature_matches_message.
func (s *Signer) verifySignatureMatchesMessage(signature solana.Signature, message []byte) error {
	if core.VerifyEd25519(s.publicKey, message, signature) {
		return nil
	}
	return core.NewSignerError(core.CodeSigningFailed, "Crossmint returned a signature for different bytes")
}

// decodeBase58Signature decodes a base58 string into a 64-byte signature.
// Port of the Rust decode_base58_signature.
func decodeBase58Signature(signatureStr string) (solana.Signature, bool) {
	raw, err := base58.Decode(signatureStr)
	if err != nil || len(raw) != core.SignatureLength {
		return solana.Signature{}, false
	}
	var sig solana.Signature
	copy(sig[:], raw)
	return sig, true
}

// sleepContext waits for d or until ctx is cancelled (the Go analog of the
// Rust tokio::time::sleep between polls).
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return core.WrapSignerError(core.CodeHTTPError, "transaction polling cancelled", ctx.Err())
	case <-timer.C:
		return nil
	}
}
