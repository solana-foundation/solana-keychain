package fordefi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// Signer signs with a Solana key held in a Fordefi vault. All fields are
// immutable after New, so a Signer is safe for concurrent use.
//
// Two signing modes are supported, selected by Config.Chain:
//   - Black box (default, Chain empty): signs the caller's exact message bytes
//     via black_box_signature; the caller broadcasts the signed transaction.
//     See SignTransaction.
//   - Native Solana (Chain set): submits solana_transaction requests with
//     push_mode "auto"; Fordefi may replace the blockhash and fees, signs,
//     and broadcasts the transaction itself. See SignAndSendTransaction.
type Signer struct {
	accessToken     string
	vaultID         string
	requestSigner   RequestSigner
	pubkey          solana.PublicKey
	apiBaseURL      string
	client          *http.Client
	pollInterval    time.Duration
	maxPollAttempts int
	chain           Chain
	fee             *Fee
}

// Ensure Signer satisfies the core contract at compile time.
var (
	_ core.Signer                 = (*Signer)(nil)
	_ core.TransactionBroadcaster = (*Signer)(nil)
)

// New builds a Fordefi signer from cfg. Construction is pure: no network I/O.
// The configured PublicKey is the source of truth for the signer's identity
// (trusted-provider model); every produced signature is verified against it.
func New(_ context.Context, cfg Config) (*Signer, error) {
	if cfg.AccessToken == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "access_token must not be empty")
	}
	if cfg.VaultID == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "vault_id must not be empty")
	}
	if cfg.PublicKey == "" {
		return nil, core.NewSignerError(core.CodeConfigError, "public_key must not be empty")
	}
	if cfg.PrivateKeyPEM != "" && cfg.RequestSigner != nil {
		return nil, core.NewSignerError(core.CodeConfigError,
			"provide exactly one of private_key_pem or request_signer, not both")
	}
	if cfg.PrivateKeyPEM == "" && cfg.RequestSigner == nil {
		return nil, core.NewSignerError(core.CodeConfigError,
			"one of private_key_pem or request_signer must be provided")
	}
	if cfg.Chain != "" && cfg.Chain != ChainSolanaDevnet && cfg.Chain != ChainSolanaMainnet {
		return nil, core.NewSignerError(core.CodeConfigError,
			"chain must be one of solana_devnet, solana_mainnet")
	}
	if cfg.Fee != nil && cfg.Chain == "" {
		return nil, core.NewSignerError(core.CodeConfigError,
			"fee requires chain to be set (native Solana mode)")
	}

	requestSigner := cfg.RequestSigner
	if requestSigner == nil {
		pemSigner, err := NewPemRequestSigner(cfg.PrivateKeyPEM)
		if err != nil {
			return nil, err
		}
		requestSigner = pemSigner
	}

	apiBaseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}

	pubkey, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid Solana public key format", err)
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)
	pollInterval, maxPollAttempts, err := core.ResolvePollBounds(
		cfg.PollInterval, DefaultPollInterval, cfg.MaxPollAttempts, DefaultMaxPollAttempts)
	if err != nil {
		return nil, err
	}

	return &Signer{
		accessToken:     cfg.AccessToken,
		vaultID:         cfg.VaultID,
		requestSigner:   requestSigner,
		pubkey:          pubkey,
		apiBaseURL:      apiBaseURL,
		client:          client,
		pollInterval:    pollInterval,
		maxPollAttempts: maxPollAttempts,
		chain:           cfg.Chain,
		fee:             cfg.Fee,
	}, nil
}

// Pubkey returns the vault's Solana public key (as configured).
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// BroadcastsTransactions reports whether SignTransaction auto-broadcasts
// (native mode).
func (s *Signer) BroadcastsTransactions() bool { return s.chain != "" }

// String renders the signer without any secret material.
func (s Signer) String() string {
	return "fordefi.Signer{pubkey: " + s.pubkey.String() +
		", vaultID: " + s.vaultID + ", apiBaseURL: " + s.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage signs arbitrary bytes via Fordefi MPC and returns the verified
// 64-byte signature. Black-box mode signs the exact bytes; native mode submits
// them as a solana_message personal message.
func (s *Signer) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	var signature solana.Signature
	var err error
	if s.chain != "" {
		signature, err = s.signSolanaMessage(ctx, message)
	} else {
		signature, err = s.signBlackBox(ctx, message)
	}
	if err != nil {
		return solana.Signature{}, err
	}
	if err := core.VerifySignature(s.pubkey, message, signature); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// SignTransaction signs tx via Fordefi MPC.
//
// Black-box mode signs the exact message bytes, places the signature at this
// signer's required-signer position in tx, and returns the encoded transaction
// for the caller to broadcast.
//
// Native mode (Chain set) submits the message with push_mode "auto": Fordefi
// may replace the blockhash (and optionally fees), signs, and broadcasts the
// transaction itself. tx is left untouched and the returned EncodedTransaction
// is empty — the transaction is already on-chain, so there is nothing for the
// caller to send; the returned signature is the on-chain identifier. Only
// transactions whose sole required signer is the configured vault are
// supported.
//
// Native mode is not retry-safe: any failure after Fordefi accepts the
// submission returns CodeBroadcastUnconfirmed carrying the Fordefi transaction
// id; check that transaction with Fordefi before retrying. A submission that
// fails without a usable response returns CodeBroadcastUnconfirmed with no
// transaction id.
//
// Each native create carries an x-idempotence-id derived from the message bytes,
// so replaying these exact bytes cannot create a second Fordefi transaction; a
// rebuilt transaction derives a different id and is broadcast again.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if s.chain != "" {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi native mode broadcasts through its own API; call SignAndSendTransaction instead")
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	signature, err := s.signBlackBox(ctx, messageBytes)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if err := core.VerifySignature(s.pubkey, messageBytes, signature); err != nil {
		return core.SignedTransaction{}, err
	}
	return core.AttachSignature(tx, s.pubkey, signature)
}

// SignAndSendTransaction signs tx and lets Fordefi broadcast it, which only
// native mode does. Fordefi replaces the blockhash (and optionally fees) and
// signs its own bytes, so tx is left untouched and the returned signature
// identifies the transaction that landed.
func (s *Signer) SignAndSendTransaction(ctx context.Context, tx *solana.Transaction) (solana.Signature, error) {
	if s.chain == "" {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi black-box mode only signs; sign the transaction and broadcast the result")
	}
	signed, err := s.signTransactionNative(ctx, tx)
	if err != nil {
		return solana.Signature{}, err
	}
	return signed.Signature, nil
}

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are
// swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	actx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	if err := s.probeVault(actx); err != nil {
		return false
	}
	_, err := s.signRequest(actx, "/api/v1/vaults", time.Now().UnixMilli(), "")
	return err == nil
}

// signBlackBox signs data via the black-box path: submit, poll, extract.
func (s *Signer) signBlackBox(ctx context.Context, data []byte) (solana.Signature, error) {
	txID, err := s.submitTransaction(ctx, transactionRequest{
		VaultID:    s.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "black_box_signature",
		Details: blackBoxDetails{
			Format:     "hash_binary",
			HashBinary: base64.StdEncoding.EncodeToString(data),
		},
	}, "", false)
	if err != nil {
		return solana.Signature{}, err
	}
	result, err := s.pollForResult(ctx, txID, false)
	if err != nil {
		return solana.Signature{}, err
	}
	return extractSignature(result)
}

// signSolanaMessage signs message via the native solana_message path.
func (s *Signer) signSolanaMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	txID, err := s.submitTransaction(ctx, transactionRequest{
		VaultID:    s.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "solana_message",
		Details: solanaMessageDetails{
			Type:    "personal_message_type",
			Chain:   s.chain,
			RawData: base64.StdEncoding.EncodeToString(message),
		},
	}, "", false)
	if err != nil {
		return solana.Signature{}, err
	}
	result, err := s.pollForResult(ctx, txID, false)
	if err != nil {
		return solana.Signature{}, err
	}
	return extractSignature(result)
}

// requireSoleRequiredSigner rejects native-mode transactions with additional
// required signers: native auto-broadcast submits message bytes only, so other
// signers' partial signatures would be dropped.
func (s *Signer) requireSoleRequiredSigner(tx *solana.Transaction) error {
	if tx.Message.Header.NumRequiredSignatures != 1 ||
		len(tx.Message.AccountKeys) == 0 || tx.Message.AccountKeys[0] != s.pubkey {
		return core.NewSignerError(core.CodeSigningFailed,
			"Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault")
	}
	return nil
}

// signTransactionNative signs tx via the native solana_transaction path.
// Fordefi may modify the transaction (at minimum the blockhash), so the
// signature is verified against the returned message bytes; tx is left
// untouched.
func (s *Signer) signTransactionNative(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if err := s.requireSoleRequiredSigner(tx); err != nil {
		return core.SignedTransaction{}, err
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	txID, err := s.submitTransaction(ctx, transactionRequest{
		VaultID:    s.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "solana_transaction",
		Details: solanaTransactionDetails{
			Type:     "solana_serialized_transaction_message",
			Chain:    s.chain,
			Data:     base64.StdEncoding.EncodeToString(messageBytes),
			PushMode: "auto",
			Fee:      s.fee,
		},
	}, core.IdempotencyKeyFromMessage(messageBytes), true)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	// Once the submit is accepted Fordefi is already broadcasting (push_mode
	// "auto"), so any later failure leaves an on-chain outcome this client
	// cannot rule out. Report those as CodeBroadcastUnconfirmed carrying the
	// Fordefi transaction id instead of a generic error a caller might blindly
	// retry into a duplicate spend.
	signed, err := s.finishNativeBroadcast(ctx, txID)
	if err != nil {
		detail := err.Error()
		var se *core.SignerError
		if errors.As(err, &se) {
			detail = se.Detail()
		}
		return core.SignedTransaction{}, core.NewBroadcastUnconfirmedError(txID, detail)
	}
	return signed, nil
}

// finishNativeBroadcast polls a submitted native transaction to completion and
// extracts and verifies the vault's signature from the returned wire bytes.
func (s *Signer) finishNativeBroadcast(ctx context.Context, txID string) (core.SignedTransaction, error) {
	result, err := s.pollForResult(ctx, txID, true)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	if result.RawTransaction == "" {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi solana_transaction response missing raw_transaction")
	}
	wireBytes, err := base64.StdEncoding.DecodeString(result.RawTransaction)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode raw_transaction base64", err)
	}
	returned, err := solana.TransactionFromBytes(wireBytes)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize Fordefi wire transaction", err)
	}

	position, err := core.SigningPosition(returned, s.pubkey)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if position >= len(returned.Signatures) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi signature slot missing from returned transaction")
	}
	signature := returned.Signatures[position]

	returnedMessage, err := returned.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Fordefi-returned transaction message", err)
	}
	if !core.VerifyEd25519(s.pubkey, returnedMessage, signature) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed against Fordefi-returned message")
	}

	return core.Classify(returned, "", signature), nil
}
