package fordefi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
)

// signerCore holds the credentials, identity and transport shared by the three
// Fordefi signing modes. All fields are immutable once built.
type signerCore struct {
	accessToken     string
	vaultID         string
	requestSigner   RequestSigner
	pubkey          solana.PublicKey
	apiBaseURL      string
	client          *http.Client
	pollInterval    time.Duration
	maxPollAttempts int
}

// buildCore validates the parts of cfg both modes share and resolves the
// transport. Construction is pure: no network I/O. The configured PublicKey is
// the source of truth for the signer's identity (trusted-provider model); every
// produced signature is verified against it.
func buildCore(cfg Config) (signerCore, error) {
	if cfg.AccessToken == "" {
		return signerCore{}, core.NewSignerError(core.CodeConfigError, "access_token must not be empty")
	}
	if cfg.VaultID == "" {
		return signerCore{}, core.NewSignerError(core.CodeConfigError, "vault_id must not be empty")
	}
	if cfg.PublicKey == "" {
		return signerCore{}, core.NewSignerError(core.CodeConfigError, "public_key must not be empty")
	}
	if cfg.PrivateKeyPEM != "" && cfg.RequestSigner != nil {
		return signerCore{}, core.NewSignerError(core.CodeConfigError,
			"provide exactly one of private_key_pem or request_signer, not both")
	}
	if cfg.PrivateKeyPEM == "" && cfg.RequestSigner == nil {
		return signerCore{}, core.NewSignerError(core.CodeConfigError,
			"one of private_key_pem or request_signer must be provided")
	}

	requestSigner := cfg.RequestSigner
	if requestSigner == nil {
		pemSigner, err := NewPemRequestSigner(cfg.PrivateKeyPEM)
		if err != nil {
			return signerCore{}, err
		}
		requestSigner = pemSigner
	}

	apiBaseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return signerCore{}, err
	}

	pubkey, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return signerCore{}, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid Solana public key format", err)
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)
	pollInterval, maxPollAttempts, err := core.ResolvePollBounds(
		cfg.PollInterval, DefaultPollInterval, cfg.MaxPollAttempts, DefaultMaxPollAttempts)
	if err != nil {
		return signerCore{}, err
	}

	return signerCore{
		accessToken:     cfg.AccessToken,
		vaultID:         cfg.VaultID,
		requestSigner:   requestSigner,
		pubkey:          pubkey,
		apiBaseURL:      apiBaseURL,
		client:          client,
		pollInterval:    pollInterval,
		maxPollAttempts: maxPollAttempts,
	}, nil
}

// isAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are swallowed
// and reported as false.
func (s *signerCore) isAvailable(ctx context.Context) bool {
	actx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	if err := s.probeVault(actx); err != nil {
		return false
	}
	_, err := s.signRequest(actx, "/api/v1/vaults", time.Now().UnixMilli(), "")
	return err == nil
}

// signBlackBox signs data via the black-box path: submit, poll, extract.
func (s *signerCore) signBlackBox(ctx context.Context, data []byte) (solana.Signature, error) {
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

// signSolanaMessage signs message on chain via the native solana_message path.
func (s *signerCore) signSolanaMessage(ctx context.Context, chain Chain, message []byte) (solana.Signature, error) {
	txID, err := s.submitTransaction(ctx, transactionRequest{
		VaultID:    s.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "solana_message",
		Details: solanaMessageDetails{
			Type:    "personal_message_type",
			Chain:   chain,
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

// New builds the Fordefi signer cfg selects: a *NativeManualSigner when Chain is
// set and PushMode is PushModeManual, a *NativeAutoSigner when Chain is set
// otherwise, and a *BlackBoxSigner when Chain is unset. Construction is pure: no
// network I/O.
func New(ctx context.Context, cfg Config) (core.SolanaSigner, error) {
	if cfg.Chain != "" {
		if cfg.PushMode == PushModeManual {
			s, err := NewNativeManual(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return s, nil
		}
		s, err := NewNativeAuto(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	s, err := NewBlackBox(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// requireNativeChain rejects a config that does not select a supported native
// Solana chain.
func requireNativeChain(chain Chain) error {
	if chain == "" {
		return core.NewSignerError(core.CodeConfigError,
			"chain must be set for native Solana mode; use NewBlackBox without it")
	}
	if chain != ChainSolanaDevnet && chain != ChainSolanaMainnet {
		return core.NewSignerError(core.CodeConfigError,
			"chain must be one of solana_devnet, solana_mainnet")
	}
	return nil
}

// requirePushMode rejects a config whose push mode is unknown or selects a
// different native mode than want. An empty push mode means PushModeAuto.
func requirePushMode(got, want PushMode, otherConstructor string) error {
	if got == "" {
		got = PushModeAuto
	}
	if got != PushModeAuto && got != PushModeManual {
		return core.NewSignerError(core.CodeConfigError, "push_mode must be one of auto, manual")
	}
	if got != want {
		return core.NewSignerError(core.CodeConfigError,
			"push_mode "+string(got)+" selects the other native mode; use "+otherConstructor)
	}
	return nil
}

// BlackBoxSigner signs with a Solana key held in a Fordefi vault via
// black_box_signature: it signs the caller's exact message bytes and the caller
// broadcasts the signed transaction. All fields are immutable after
// construction, so a BlackBoxSigner is safe for concurrent use.
type BlackBoxSigner struct {
	core signerCore
}

// Ensure BlackBoxSigner satisfies the core contract at compile time.
var _ core.TransactionSigner = (*BlackBoxSigner)(nil)

// NewBlackBox builds a black-box Fordefi signer from cfg. Chain, Fee and
// PushMode select native Solana mode and must be unset; use NewNativeAuto or
// NewNativeManual for those.
func NewBlackBox(_ context.Context, cfg Config) (*BlackBoxSigner, error) {
	if cfg.Chain != "" || cfg.Fee != nil || cfg.PushMode != "" {
		return nil, core.NewSignerError(core.CodeConfigError,
			"chain, fee and push_mode select native Solana mode; use NewNativeAuto or NewNativeManual")
	}
	built, err := buildCore(cfg)
	if err != nil {
		return nil, err
	}
	return &BlackBoxSigner{core: built}, nil
}

// Pubkey returns the vault's Solana public key (as configured).
func (s *BlackBoxSigner) Pubkey() solana.PublicKey { return s.core.pubkey }

// String renders the signer without any secret material.
func (s BlackBoxSigner) String() string {
	return "fordefi.BlackBoxSigner{pubkey: " + s.core.pubkey.String() +
		", vaultID: " + s.core.vaultID + ", apiBaseURL: " + s.core.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s BlackBoxSigner) GoString() string { return s.String() }

// SignMessage signs the exact bytes via Fordefi MPC and returns the verified
// 64-byte signature.
func (s *BlackBoxSigner) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	signature, err := s.core.signBlackBox(ctx, message)
	if err != nil {
		return solana.Signature{}, err
	}
	if err := core.VerifySignature(s.core.pubkey, message, signature); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// SignTransaction signs tx's exact message bytes via Fordefi MPC, places the
// signature at this signer's required-signer position in tx, and returns the
// encoded transaction for the caller to broadcast.
func (s *BlackBoxSigner) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	signature, err := s.core.signBlackBox(ctx, messageBytes)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if err := core.VerifySignature(s.core.pubkey, messageBytes, signature); err != nil {
		return core.SignedTransaction{}, err
	}
	return core.AttachSignature(tx, s.core.pubkey, signature)
}

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are swallowed
// and reported as false.
func (s *BlackBoxSigner) IsAvailable(ctx context.Context) bool { return s.core.isAvailable(ctx) }

// NativeAutoSigner submits solana_transaction requests with push_mode "auto":
// Fordefi may replace the blockhash and fees, signs, and broadcasts the
// transaction itself. All fields are immutable after construction, so a
// NativeAutoSigner is safe for concurrent use.
type NativeAutoSigner struct {
	core  signerCore
	chain Chain
	fee   *Fee
}

// Ensure NativeAutoSigner satisfies the core contract at compile time.
var _ core.SendingSigner = (*NativeAutoSigner)(nil)

// NewNativeAuto builds an auto-broadcasting native Solana Fordefi signer from
// cfg. Chain must be set; leave it empty and use NewBlackBox for black-box
// signing. PushMode must be empty or PushModeAuto; use NewNativeManual for
// PushModeManual.
func NewNativeAuto(_ context.Context, cfg Config) (*NativeAutoSigner, error) {
	if err := requireNativeChain(cfg.Chain); err != nil {
		return nil, err
	}
	if err := requirePushMode(cfg.PushMode, PushModeAuto, "NewNativeManual"); err != nil {
		return nil, err
	}
	built, err := buildCore(cfg)
	if err != nil {
		return nil, err
	}
	return &NativeAutoSigner{core: built, chain: cfg.Chain, fee: cfg.Fee}, nil
}

// Pubkey returns the vault's Solana public key (as configured).
func (s *NativeAutoSigner) Pubkey() solana.PublicKey { return s.core.pubkey }

// String renders the signer without any secret material.
func (s NativeAutoSigner) String() string {
	return "fordefi.NativeAutoSigner{pubkey: " + s.core.pubkey.String() +
		", vaultID: " + s.core.vaultID + ", apiBaseURL: " + s.core.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s NativeAutoSigner) GoString() string { return s.String() }

// SignMessage submits message as a solana_message personal message and returns
// the verified 64-byte signature.
func (s *NativeAutoSigner) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	signature, err := s.core.signSolanaMessage(ctx, s.chain, message)
	if err != nil {
		return solana.Signature{}, err
	}
	if err := core.VerifySignature(s.core.pubkey, message, signature); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// SignAndSendTransaction submits tx's message with push_mode "auto": Fordefi may
// replace the blockhash (and optionally fees), signs, and broadcasts the
// transaction itself. tx is left untouched and the returned signature is the
// on-chain identifier. Only transactions whose sole required signer is the
// configured vault, and which carry no signature yet, are supported.
//
// Not retry-safe: any failure after Fordefi accepts the submission returns
// CodeBroadcastUnconfirmed carrying the Fordefi transaction id; check that
// transaction with Fordefi before retrying. A submission that fails without a
// usable response returns CodeBroadcastUnconfirmed with no transaction id.
//
// Each create carries an x-idempotence-id derived from the message bytes under
// the push mode, chain, vault and fee it was submitted with, so replaying these
// exact bytes on the same terms reuses the Fordefi request.
func (s *NativeAutoSigner) SignAndSendTransaction(ctx context.Context, tx *solana.Transaction) (solana.Signature, error) {
	signed, err := s.signTransactionNative(ctx, tx)
	if err != nil {
		return solana.Signature{}, err
	}
	return signed.Signature, nil
}

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are swallowed
// and reported as false.
func (s *NativeAutoSigner) IsAvailable(ctx context.Context) bool { return s.core.isAvailable(ctx) }

// requireSoleRequiredSigner rejects native-mode transactions with additional
// required signers: native auto-broadcast submits message bytes only, so other
// signers' partial signatures would be dropped.
//
// A signature already present can only be the vault's own over these bytes,
// which means they may already be on chain. Fordefi replaces the blockhash
// before broadcasting, so the result would be a second transaction carrying the
// same transfer, outside the network's replay protection.
func (s *NativeAutoSigner) requireSoleRequiredSigner(tx *solana.Transaction) error {
	if tx.Message.Header.NumRequiredSignatures != 1 ||
		len(tx.Message.AccountKeys) == 0 || tx.Message.AccountKeys[0] != s.core.pubkey {
		return core.NewSignerError(core.CodeSigningFailed,
			"Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault")
	}
	for _, signature := range tx.Signatures {
		if !signature.IsZero() {
			return core.NewSignerError(core.CodeSigningFailed,
				"Fordefi native auto-broadcast must run before any transaction signatures are applied")
		}
	}
	return nil
}

// signTransactionNative signs tx via the native solana_transaction path.
// Fordefi may modify the transaction (at minimum the blockhash), so the
// signature is verified against the returned message bytes; tx is left
// untouched.
func (s *NativeAutoSigner) signTransactionNative(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if err := s.requireSoleRequiredSigner(tx); err != nil {
		return core.SignedTransaction{}, err
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	txID, err := s.core.submitTransaction(ctx, transactionRequest{
		VaultID:    s.core.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "solana_transaction",
		Details: solanaTransactionDetails{
			Type:     "solana_serialized_transaction_message",
			Chain:    s.chain,
			Data:     base64.StdEncoding.EncodeToString(messageBytes),
			PushMode: PushModeAuto,
			Fee:      s.fee,
		},
	}, nativeIdempotencyKey(PushModeAuto, s.chain, s.core.vaultID, s.fee, messageBytes), true)
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
func (s *NativeAutoSigner) finishNativeBroadcast(ctx context.Context, txID string) (core.SignedTransaction, error) {
	result, err := s.core.pollForResult(ctx, txID, true)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	returned, signature, err := extractAndVerifyRewritten(result, s.core.pubkey)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(returned, "", signature), nil
}

// NativeManualSigner submits solana_transaction requests with push_mode
// "manual": Fordefi rewrites the message and signs it, but leaves the broadcast
// to the caller. All fields are immutable after construction, so a
// NativeManualSigner is safe for concurrent use.
type NativeManualSigner struct {
	core  signerCore
	chain Chain
	fee   *Fee
}

// Ensure NativeManualSigner satisfies the core contract at compile time.
var _ core.ModifyingSigner = (*NativeManualSigner)(nil)

// NewNativeManual builds a non-broadcasting native Solana Fordefi signer from
// cfg. Chain must be set and PushMode must be PushModeManual; use NewNativeAuto
// for the auto-broadcasting mode and NewBlackBox for black-box signing.
func NewNativeManual(_ context.Context, cfg Config) (*NativeManualSigner, error) {
	if err := requireNativeChain(cfg.Chain); err != nil {
		return nil, err
	}
	if err := requirePushMode(cfg.PushMode, PushModeManual, "NewNativeAuto"); err != nil {
		return nil, err
	}
	built, err := buildCore(cfg)
	if err != nil {
		return nil, err
	}
	return &NativeManualSigner{core: built, chain: cfg.Chain, fee: cfg.Fee}, nil
}

// Pubkey returns the vault's Solana public key (as configured).
func (s *NativeManualSigner) Pubkey() solana.PublicKey { return s.core.pubkey }

// String renders the signer without any secret material.
func (s NativeManualSigner) String() string {
	return "fordefi.NativeManualSigner{pubkey: " + s.core.pubkey.String() +
		", vaultID: " + s.core.vaultID + ", apiBaseURL: " + s.core.apiBaseURL + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s NativeManualSigner) GoString() string { return s.String() }

// SignMessage submits message as a solana_message personal message and returns
// the verified 64-byte signature.
func (s *NativeManualSigner) SignMessage(ctx context.Context, message []byte) (solana.Signature, error) {
	signature, err := s.core.signSolanaMessage(ctx, s.chain, message)
	if err != nil {
		return solana.Signature{}, err
	}
	if err := core.VerifySignature(s.core.pubkey, message, signature); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are swallowed
// and reported as false.
func (s *NativeManualSigner) IsAvailable(ctx context.Context) bool { return s.core.isAvailable(ctx) }

// ModifyAndSignTransaction submits tx's message with push_mode "manual". Fordefi
// rewrites the message, at minimum the recent blockhash, and it manages the
// Compute Budget fee instructions, then signs without broadcasting. tx is
// replaced with the bytes the returned signature covers, so it can never hold a
// message nothing signed, and the caller broadcasts the encoded result.
//
// The rewrite itself is not diffed: what Keychain validates is the signing hop,
// by verifying the returned signature at the vault's required-signer position
// against the message Fordefi returned. Preconditions on the caller's input do
// apply: the vault must be the fee payer.
//
// Each create carries an x-idempotence-id derived from the message bytes under
// the push mode, chain, vault and fee it was submitted with, so a resend on the
// same terms reuses the Fordefi transaction instead of creating a second one.
func (s *NativeManualSigner) ModifyAndSignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if err := s.requireVaultPaidTransaction(tx); err != nil {
		return core.SignedTransaction{}, err
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError, "failed to serialize transaction message", err)
	}
	txID, err := s.core.submitTransaction(ctx, transactionRequest{
		VaultID:    s.core.vaultID,
		SignerType: "api_signer",
		SignMode:   "auto",
		Type:       "solana_transaction",
		Details: solanaTransactionDetails{
			Type:     "solana_serialized_transaction_message",
			Chain:    s.chain,
			Data:     base64.StdEncoding.EncodeToString(messageBytes),
			PushMode: PushModeManual,
			Fee:      s.fee,
		},
	}, s.idempotencyKey(messageBytes), false)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	result, err := s.core.pollForResult(ctx, txID, false)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	returned, signature, err := extractAndVerifyRewritten(result, s.core.pubkey)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(returned)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	*tx = *returned
	return core.Classify(tx, encoded, signature), nil
}

// requireVaultPaidTransaction rejects a transaction Fordefi may not rewrite: it
// only signs one it pays for.
func (s *NativeManualSigner) requireVaultPaidTransaction(tx *solana.Transaction) error {
	if len(tx.Message.AccountKeys) == 0 || tx.Message.AccountKeys[0] != s.core.pubkey {
		return core.NewSignerError(core.CodeSigningFailed,
			"Fordefi native manual signing requires the configured vault to be the transaction fee payer")
	}
	return nil
}

// idempotencyKey namespaces the manual key so the same message bytes cannot
// collide with an earlier create carrying other terms.
func (s *NativeManualSigner) idempotencyKey(messageBytes []byte) string {
	return nativeIdempotencyKey(PushModeManual, s.chain, s.core.vaultID, s.fee, messageBytes)
}

// nativeIdempotencyKey binds a native key to the push mode, chain, vault and fee
// the create carries, so identical message bytes submitted under different terms
// are not deduplicated into each other.
func nativeIdempotencyKey(pushMode PushMode, chain Chain, vaultID string, fee *Fee, messageBytes []byte) string {
	namespaced := []byte("fordefi:solana:" + string(pushMode) + ":" + string(chain) + ":" +
		vaultID + ":" + canonicalFee(fee) + ":")
	return core.IdempotencyKeyFromMessage(append(namespaced, messageBytes...))
}

// canonicalFee renders a fee as type|priority_level|unit_price|priority_fee. The
// field order is fixed so a key derived from it stays stable.
func canonicalFee(fee *Fee) string {
	if fee == nil {
		return ""
	}
	return fee.Type + "|" + string(fee.PriorityLevel) + "|" + fee.UnitPrice + "|" + fee.PriorityFee
}

// extractAndVerifyRewritten decodes the wire transaction a native response
// carries and verifies the vault's signature, taken from its required-signer
// position, against the message those bytes carry. Fordefi rewrites the message
// before signing it, so the submitted bytes are not what the signature covers.
func extractAndVerifyRewritten(result transactionStatusResponse, pubkey solana.PublicKey) (*solana.Transaction, solana.Signature, error) {
	if result.RawTransaction == "" {
		return nil, solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi solana_transaction response missing raw_transaction")
	}
	wireBytes, err := base64.StdEncoding.DecodeString(result.RawTransaction)
	if err != nil {
		return nil, solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode raw_transaction base64", err)
	}
	returned, err := solana.TransactionFromBytes(wireBytes)
	if err != nil {
		return nil, solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize Fordefi wire transaction", err)
	}

	position, err := core.SigningPosition(returned, pubkey)
	if err != nil {
		return nil, solana.Signature{}, err
	}
	if position >= len(returned.Signatures) {
		return nil, solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi signature slot missing from returned transaction")
	}
	signature := returned.Signatures[position]

	returnedMessage, err := returned.Message.MarshalBinary()
	if err != nil {
		return nil, solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Fordefi-returned transaction message", err)
	}
	if !core.VerifyEd25519(pubkey, returnedMessage, signature) {
		return nil, solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed against Fordefi-returned message")
	}
	return returned, signature, nil
}
