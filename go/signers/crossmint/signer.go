package crossmint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// awaitingApprovalDetail is the error detail used whenever a transaction is
// stuck awaiting approvals this signer cannot provide.
const awaitingApprovalDetail = "Crossmint transaction is awaiting approval; additional signer approvals are required"

// Signer signs transactions through the Crossmint Wallets API: transactions
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
	// delegatedPubkeys are every delegated-signer key the configuration makes
	// known. Smart wallets sign with one of these rather than with publicKey.
	delegatedPubkeys []solana.PublicKey
	// signingKey is the HKDF-derived Ed25519 approval key (nil when no
	// SignerSecret was configured).
	signingKey ed25519.PrivateKey
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Crossmint signer and resolves the wallet's public key, so the
// returned signer is ready to use.
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
	s.delegatedPubkeys = resolveDelegatedPubkeys(signingKey, signerLocator)

	return s, nil
}

// resolveDelegatedPubkeys returns every delegated-signer key the configuration
// makes known. A smart wallet signs through its delegated signer, not the wallet
// address. Both sources are collected because a Signer locator may name a
// different key than SignerSecret derives, and either can be the one that signs.
func resolveDelegatedPubkeys(signingKey ed25519.PrivateKey, signerLocator string) []solana.PublicKey {
	var candidates []solana.PublicKey
	if signingKey != nil {
		candidates = append(candidates, solana.PublicKeyFromBytes(signingKey.Public().(ed25519.PublicKey)))
	}
	if encoded, ok := strings.CutPrefix(signerLocator, "server:"); ok {
		if pub, err := solana.PublicKeyFromBase58(strings.TrimSpace(encoded)); err == nil {
			candidates = append(candidates, pub)
		}
	}
	return candidates
}

// verificationCandidates lists the keys that may have signed: the wallet address
// for an mpc wallet, the delegated signer for a smart wallet. The response does
// not say which, so try both.
func (s *Signer) verificationCandidates() []solana.PublicKey {
	candidates := []solana.PublicKey{s.publicKey}
	for _, delegated := range s.delegatedPubkeys {
		if !slices.Contains(candidates, delegated) {
			candidates = append(candidates, delegated)
		}
	}
	return candidates
}

// Pubkey returns the Crossmint wallet's Solana public key.
func (s *Signer) Pubkey() solana.PublicKey { return s.publicKey }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "crossmint.Signer{pubkey: " + s.publicKey.String() + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage is intentionally unsupported: Crossmint does not expose raw
// message signing for Solana wallets, so this always fails with
// CodeSigningFailed.
func (s *Signer) SignMessage(_ context.Context, _ []byte) (solana.Signature, error) {
	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"Crossmint sign_message is not supported for Solana wallets in this signer")
}

// idempotencyKeyFromMessage derives a UUID from SHA-256(message bytes), so a
// retry of the same bytes reuses the key and Crossmint deduplicates the create.
func idempotencyKeyFromMessage(messageBytes []byte) string {
	digest := sha256.Sum256(messageBytes)
	key := digest[:16]
	key[6] = (key[6] & 0x0f) | 0x40
	key[8] = (key[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", key[0:4], key[4:6], key[6:8], key[8:10], key[10:16])
}

// SignTransaction submits tx to Crossmint, polls it to completion, and extracts
// and verifies the wallet's signature.
//
// Crossmint may rewrite the transaction to sponsor gas and broadcast it itself.
// When it does, tx is left unmodified, EncodedTransaction is empty, and the
// returned signature is the landed transaction's fee-payer identifier, usable
// with RPC transaction lookups. The wallet's own signature is added to tx only
// when Crossmint signed it as given.
//
// Not retry-safe: any failure after the create is accepted returns
// CodeBroadcastUnconfirmed carrying the Crossmint transaction id; check that
// transaction with Crossmint before retrying. Each create carries an
// x-idempotency-key derived from the message bytes, so retrying the exact
// same bytes cannot create a second transaction.
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

	createResponse, err := s.createTransaction(ctx, base58.Encode(serialized), idempotencyKeyFromMessage(expectedMessage))
	if err != nil {
		return core.SignedTransaction{}, err
	}
	// Post-create failures leave an outcome Crossmint may still execute, so
	// they surface as CodeBroadcastUnconfirmed with the transaction id.
	signed, err := s.finishManagedTransaction(ctx, tx, createResponse, expectedMessage)
	if err != nil {
		detail := err.Error()
		var se *core.SignerError
		if errors.As(err, &se) {
			detail = se.Detail()
		}
		return core.SignedTransaction{}, core.NewBroadcastUnconfirmedError(createResponse.ID, detail)
	}
	return signed, nil
}

// finishManagedTransaction polls a created transaction to a terminal status and
// shapes the signing result from it.
func (s *Signer) finishManagedTransaction(ctx context.Context, tx *solana.Transaction, createResponse transactionResponse, expectedMessage []byte) (core.SignedTransaction, error) {
	finalResponse, err := s.pollTransaction(ctx, createResponse)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	sig, broadcast, err := s.extractSignatureFromResponse(finalResponse, expectedMessage)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	if broadcast != nil {
		// Already landed, so complete regardless of the slots the returned copy
		// shows filled, and nothing is left for the caller to send.
		return core.SignedTransaction{Signature: sig, Completeness: core.Complete}, nil
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
// availability timeout. Errors are swallowed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, availabilityTimeout)
	defer cancel()
	_, err := s.fetchWallet(ctx)
	return err == nil
}

// pollTransaction drives a created transaction to a terminal state: "success"
// returns, "failed" errors, the first "awaiting-approval" triggers a single
// approval attempt, and anything else waits pollInterval and re-fetches, for
// at most maxPollAttempts iterations before the final-status check.
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
// carrying the (sanitized) remote error payload.
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
// key is configured or no matching challenge is pending.
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

// signatureFromApprovals finds this wallet's signature over the transaction
// Crossmint executed. For a rewritten transaction it arrives in
// approvals.submitted covering the rewritten message, not in a signature slot.
// Verified locally regardless.
func (s *Signer) signatureFromApprovals(response transactionResponse, serializedTransaction string) (solana.Signature, *solana.Transaction, bool) {
	if response.Approvals == nil || len(response.Approvals.Submitted) == 0 {
		return solana.Signature{}, nil, false
	}
	raw, err := base58.Decode(serializedTransaction)
	if err != nil {
		return solana.Signature{}, nil, false
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return solana.Signature{}, nil, false
	}
	executedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, nil, false
	}
	candidates := s.verificationCandidates()
	for i := range response.Approvals.Submitted {
		entry := &response.Approvals.Submitted[i]
		if entry.Signature == nil || entry.Signer == nil || entry.Signer.Address == nil {
			continue
		}
		approver, err := solana.PublicKeyFromBase58(*entry.Signer.Address)
		if err != nil || !slices.Contains(candidates, approver) {
			continue
		}
		sig, ok := decodeBase58Signature(*entry.Signature)
		if !ok || !core.VerifyEd25519(approver, executedMessage, sig) {
			continue
		}
		return sig, tx, true
	}
	return solana.Signature{}, nil, false
}

// broadcastTransactionID returns the landed transaction's fee-payer (slot 0)
// signature, the value RPC transaction lookups accept.
func broadcastTransactionID(tx *solana.Transaction) (solana.Signature, error) {
	if len(tx.Message.AccountKeys) == 0 {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint transaction has no fee payer to identify it by")
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint transaction carries no fee-payer signature to identify it by")
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Crossmint transaction message", err)
	}
	if !core.VerifyEd25519(tx.Message.AccountKeys[0], message, tx.Signatures[0]) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint fee-payer signature does not verify over the executed transaction")
	}
	return tx.Signatures[0], nil
}

// extractSignatureFromResponse pulls this wallet's signature out of a terminal
// transaction response, along with the broadcast transaction when Crossmint
// rewrote one: the serialized onChain.transaction is tried first; onChain.txId is
// only accepted if it verifies against the originally requested message bytes.
//
// A non-nil transaction means Crossmint landed different bytes than the caller's;
// the signature is then the landed transaction's fee-payer identifier.
func (s *Signer) extractSignatureFromResponse(response transactionResponse, expectedMessage []byte) (solana.Signature, *solana.Transaction, error) {
	var embeddedErr error
	if response.OnChain != nil {
		if response.OnChain.Transaction != nil {
			sig, returned, err := s.extractSignatureFromSerializedTransaction(*response.OnChain.Transaction)
			switch {
			case err == nil:
				returnedMessage, marshalErr := returned.Message.MarshalBinary()
				if marshalErr != nil {
					return solana.Signature{}, nil, core.WrapSignerError(core.CodeSerializationError,
						"failed to serialize Crossmint transaction message", marshalErr)
				}
				if bytes.Equal(returnedMessage, expectedMessage) {
					return sig, nil, nil
				}
				txID, idErr := broadcastTransactionID(returned)
				if idErr != nil {
					return solana.Signature{}, nil, idErr
				}
				return txID, returned, nil
			case true:
				// A rewritten transaction's approval lives in approvals.submitted.
				if _, returned, ok := s.signatureFromApprovals(response, *response.OnChain.Transaction); ok {
					txID, idErr := broadcastTransactionID(returned)
					if idErr != nil {
						return solana.Signature{}, nil, idErr
					}
					return txID, returned, nil
				}
				if response.OnChain.TxID == nil {
					return solana.Signature{}, nil, err
				}
				// Keep this error as the cause: it names the check that failed,
				// where the txId path only reports a mismatch.
				embeddedErr = err
			}
		}

		if response.OnChain.TxID != nil {
			sig, ok := decodeBase58Signature(*response.OnChain.TxID)
			if !ok {
				return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
					"Crossmint onChain.txId was not a valid Solana signature")
			}
			// A txId counts only if it covers the caller's bytes, and any configured
			// signer may have produced it.
			verified := false
			for _, candidate := range s.verificationCandidates() {
				if core.VerifyEd25519(candidate, expectedMessage, sig) {
					verified = true
					break
				}
			}
			if !verified {
				if embeddedErr != nil {
					return solana.Signature{}, nil, embeddedErr
				}
				return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
					"Crossmint returned a signature for different bytes")
			}
			return sig, nil, nil
		}
	}

	return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
		"unable to extract signature from Crossmint transaction response")
}

// extractSignatureFromSerializedTransaction decodes the base58 onChain.transaction,
// locates this wallet's required-signer position, and verifies the signature
// against that transaction's own message bytes.
//
// Crossmint sponsors gas, so when it rewrites it becomes the fee payer and the
// message it signs differs from the caller's. The decoded transaction is returned
// with the signature so the caller is never handed it over its own message.
func (s *Signer) extractSignatureFromSerializedTransaction(serializedTransaction string) (solana.Signature, *solana.Transaction, error) {
	raw, err := base58.Decode(serializedTransaction)
	if err != nil {
		return solana.Signature{}, nil, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode Crossmint onChain.transaction as base58", err)
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return solana.Signature{}, nil, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize Crossmint onChain.transaction", err)
	}

	requiredSigners := int(tx.Message.Header.NumRequiredSignatures)
	signerKeys := tx.Message.AccountKeys
	if len(signerKeys) < requiredSigners {
		return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
			"invalid account index: not enough account keys")
	}

	remoteMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, nil, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Crossmint transaction message", err)
	}

	// Take the first candidate that actually carries a verifying signature, not
	// merely the first that occupies a signer slot: a wallet address can sit in a
	// slot it never signed, while the delegated signer holds the real signature.
	for _, candidate := range s.verificationCandidates() {
		for i := 0; i < requiredSigners; i++ {
			if signerKeys[i] != candidate || i >= len(tx.Signatures) || tx.Signatures[i].IsZero() {
				continue
			}
			if core.VerifyEd25519(candidate, remoteMessage, tx.Signatures[i]) {
				return tx.Signatures[i], tx, nil
			}
		}
	}
	return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
		"no configured signer holds a verifying signature in the Crossmint transaction")
}

// decodeBase58Signature decodes a base58 string into a 64-byte signature.
func decodeBase58Signature(signatureStr string) (solana.Signature, bool) {
	raw, err := base58.Decode(signatureStr)
	if err != nil || len(raw) != core.SignatureLength {
		return solana.Signature{}, false
	}
	var sig solana.Signature
	copy(sig[:], raw)
	return sig, true
}

// sleepContext waits for d or until ctx is cancelled.
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
