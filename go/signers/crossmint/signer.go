package crossmint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/base58"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// awaitingApprovalDetail is the error detail used whenever a transaction is
// stuck awaiting approvals this signer cannot provide.
const awaitingApprovalDetail = "Crossmint transaction is awaiting approval; additional signer approvals are required"

// Signer signs transactions through the Crossmint Wallets API: transactions
// are created remotely, polled to a terminal status, optionally auto-approved
// with the HKDF-derived server signer key, and the returned signature is
// extracted from the response.
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
var _ core.SendingSigner = (*Signer)(nil)

// New builds a Crossmint signer and resolves the wallet's public key, so the
// returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	if cfg.APIKey == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "api_key must not be empty")
	}
	if cfg.WalletLocator == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "wallet_locator must not be empty")
	}

	apiBaseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}

	pollInterval, maxPollAttempts, err := core.ResolvePollBounds(
		cfg.PollInterval, DefaultPollInterval, cfg.MaxPollAttempts, DefaultMaxPollAttempts)
	if err != nil {
		return nil, err
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)

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
	return s, nil
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

// SignAndSendTransaction submits tx to Crossmint, polls it to completion, and
// returns the signature identifying the transaction Crossmint landed.
//
// Crossmint may rewrite the transaction to sponsor gas, so the returned
// signature does not necessarily cover the caller's bytes; it is the landed
// transaction's identifier, usable with RPC transaction lookups. tx is never
// modified.
//
// Not retry-safe: any failure after the create is accepted returns
// CodeBroadcastUnconfirmed carrying the Crossmint transaction id; check that
// transaction with Crossmint before retrying. A create whose response carries no
// readable transaction id returns CodeBroadcastUnconfirmed with no transaction id.
//
// Each create carries an x-idempotency-key derived from the message bytes, so
// replaying these exact bytes cannot create a second transaction; a rebuilt
// transaction derives a different key and executes as a new transfer.
func (s *Signer) SignAndSendTransaction(ctx context.Context, tx *solana.Transaction) (solana.Signature, error) {
	if s.publicKey.IsZero() {
		return solana.Signature{}, core.NewNotInitializedError("crossmint")
	}

	expectedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	serialized, err := tx.MarshalBinary()
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction", err)
	}

	createResponse, err := s.createTransaction(ctx, base58.Encode(serialized), core.IdempotencyKeyFromMessage(expectedMessage))
	if err != nil {
		return solana.Signature{}, err
	}
	// Post-create failures leave an outcome Crossmint may still execute, so
	// they surface as CodeBroadcastUnconfirmed with the transaction id.
	sig, err := s.finishManagedTransaction(ctx, createResponse, expectedMessage)
	if err != nil {
		detail := err.Error()
		var se *core.SignerError
		if errors.As(err, &se) {
			detail = se.Detail()
		}
		return solana.Signature{}, core.NewBroadcastUnconfirmedError(createResponse.ID, detail)
	}
	return sig, nil
}

// finishManagedTransaction polls a created transaction to a terminal status and
// extracts the signature identifying it.
func (s *Signer) finishManagedTransaction(ctx context.Context, createResponse transactionResponse, expectedMessage []byte) (solana.Signature, error) {
	finalResponse, err := s.pollTransaction(ctx, createResponse)
	if err != nil {
		return solana.Signature{}, err
	}
	return s.extractSignatureFromResponse(finalResponse, expectedMessage)
}

// IsAvailable reports whether the Crossmint wallet can be fetched within the
// availability timeout. Errors are swallowed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
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
			if err := core.SleepContextUnconfirmed(ctx, s.pollInterval, response.ID); err != nil {
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
		return transactionResponse{}, core.PollTimeoutError("crossmint", s.maxPollAttempts)
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
	return tx.Signatures[0], nil
}

// extractSignatureFromResponse pulls the signature identifying the transaction
// Crossmint landed out of a terminal transaction response: the serialized
// onChain.transaction is tried first, with onChain.txId as a fallback when
// Crossmint does not return a decodable transaction.
//
// When Crossmint landed different bytes than the caller's, the signature is the
// landed transaction's fee-payer identifier rather than a signature over the
// caller's message.
func (s *Signer) extractSignatureFromResponse(response transactionResponse, expectedMessage []byte) (solana.Signature, error) {
	if response.OnChain != nil {
		if response.OnChain.Transaction != nil {
			sig, returned, err := s.extractSignatureFromSerializedTransaction(*response.OnChain.Transaction)
			switch {
			case err == nil:
				returnedMessage, marshalErr := returned.Message.MarshalBinary()
				if marshalErr != nil {
					return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
						"failed to serialize Crossmint transaction message", marshalErr)
				}
				if bytes.Equal(returnedMessage, expectedMessage) {
					return sig, nil
				}
				return broadcastTransactionID(returned)
			case true:
				if response.OnChain.TxID == nil {
					return solana.Signature{}, err
				}
			}
		}

		if response.OnChain.TxID != nil {
			sig, ok := decodeBase58Signature(*response.OnChain.TxID)
			if !ok {
				return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
					"Crossmint onChain.txId was not a valid Solana signature")
			}
			return sig, nil
		}
	}

	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"unable to extract signature from Crossmint transaction response")
}

// extractSignatureFromSerializedTransaction decodes the base58 onChain.transaction
// and returns its fee-payer signature, verified against that transaction's own
// message bytes.
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

	if len(signerKeys) == 0 {
		return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint transaction carries no account keys")
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint transaction carries no signer signature")
	}

	returnedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, nil, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Crossmint returned message", err)
	}
	if !core.VerifyEd25519(signerKeys[0], returnedMessage, tx.Signatures[0]) {
		return solana.Signature{}, nil, core.NewSignerError(core.CodeSigningFailed,
			"Crossmint fee-payer signature does not verify against the returned message")
	}
	return tx.Signatures[0], tx, nil
}

// decodeBase58Signature decodes a base58 string into a 64-byte signature.
func decodeBase58Signature(signatureStr string) (solana.Signature, bool) {
	sig, err := core.DecodeSignatureBase58(signatureStr, "crossmint")
	return sig, err == nil
}
