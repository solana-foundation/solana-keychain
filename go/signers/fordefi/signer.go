package fordefi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Timeouts for the two bounded probes (vault ownership verification during New
// and the IsAvailable readiness check).
const (
	vaultVerificationTimeout = 10 * time.Second
	solanaPacketDataSize     = 1232
)

// Signer signs with a Solana key held in a Fordefi vault. All fields are
// immutable after New, so a Signer is safe for concurrent use.
//
// Three signing modes are supported, selected by Config.Chain and
// Config.PushMode:
//   - Black box (default, Chain empty): signs the caller's exact message bytes
//     via black_box_signature; the caller broadcasts the signed transaction.
//   - Native auto (Chain set, PushMode empty or Auto): Fordefi may replace the
//     blockhash and fees, signs, and broadcasts the transaction itself.
//   - Native manual (Chain set, PushMode Manual): for the unsigned requests this
//     signer supports, Fordefi may replace the blockhash and manage priority-fee
//     instructions, then returns the transaction for downstream signing and
//     caller-managed broadcasting. See SignTransaction.
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
	pushMode        PushMode
	fee             *Fee

	// maxPriorityFeeLamports is nil when the caller did not state a ceiling.
	maxPriorityFeeLamports *uint64
}

// Ensure Signer satisfies the core contract at compile time.
var (
	_ core.Signer                 = (*Signer)(nil)
	_ core.TransactionBroadcaster = (*Signer)(nil)
)

// New builds a Fordefi signer and verifies that the configured PublicKey
// actually belongs to the configured VaultID (without this check a
// valid-but-wrong address would pass configuration and later be returned by
// Pubkey, creating a funds-routing risk). The returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
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
	pushMode := cfg.PushMode
	if pushMode == "" {
		pushMode = PushModeAuto
	}
	if pushMode != PushModeAuto && pushMode != PushModeManual {
		return nil, core.NewSignerError(core.CodeConfigError,
			"push_mode must be one of auto, manual")
	}
	if pushMode == PushModeManual && cfg.Chain == "" {
		return nil, core.NewSignerError(core.CodeConfigError,
			"manual push_mode requires chain to be set (native Solana mode)")
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

	s := &Signer{
		accessToken:     cfg.AccessToken,
		vaultID:         cfg.VaultID,
		requestSigner:   requestSigner,
		pubkey:          pubkey,
		apiBaseURL:      apiBaseURL,
		client:          client,
		pollInterval:    pollInterval,
		maxPollAttempts: maxPollAttempts,
		chain:           cfg.Chain,
		pushMode:        pushMode,
		fee:             cfg.Fee,

		maxPriorityFeeLamports: cfg.MaxPriorityFeeLamports,
	}

	if err := s.verifyVaultOwnership(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// verifyVaultOwnership fetches the vault and checks that its authoritative
// Solana public key matches the configured one.
func (s *Signer) verifyVaultOwnership(ctx context.Context) error {
	vctx, cancel := context.WithTimeout(ctx, vaultVerificationTimeout)
	defer cancel()
	vault, err := s.fetchVault(vctx)
	if err != nil {
		return err
	}
	remote, err := vaultPublicKey(vault)
	if err != nil {
		return err
	}
	if remote != s.pubkey {
		return core.NewSignerError(core.CodeConfigError,
			"configured public_key does not match Fordefi vault "+s.vaultID)
	}
	return nil
}

// Pubkey returns the vault's Solana public key (verified during New).
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// BroadcastsTransactions reports whether SignTransaction auto-broadcasts.
func (s *Signer) BroadcastsTransactions() bool {
	return s.chain != "" && s.pushMode == PushModeAuto
}

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
// Native auto mode submits the message with push_mode "auto": Fordefi
// may replace the blockhash (and optionally fees), signs, and broadcasts the
// transaction itself. tx is left untouched and the returned EncodedTransaction
// is empty — the transaction is already on-chain, so there is nothing for the
// caller to send; the returned signature is the on-chain identifier. Only
// transactions whose sole required signer is the configured vault are
// supported.
//
// Native auto mode is not retry-safe: any failure after Fordefi accepts the
// submission returns CodeBroadcastUnconfirmed carrying the Fordefi transaction
// id; check that transaction with Fordefi before retrying. A submission that
// fails without a usable response returns CodeBroadcastUnconfirmed with no
// transaction id.
//
// Native manual mode submits an unsigned message with push_mode "manual".
// Fordefi may replace its recent blockhash and, unless it already sets a
// compute-unit price, manage SetComputeUnitPrice/SetComputeUnitLimit. It signs
// but does not broadcast. After validating that all content outside the
// documented blockhash and fee mutation set is unchanged, SignTransaction
// replaces tx and returns its non-empty base64 encoding. Fordefi must be the
// fee payer and manual signing must happen before any other signer. A
// sole-signer result is Complete; a multisigner result is Partial so downstream
// signers can update tx before the caller broadcasts it.
// Fordefi does not provide the replacement blockhash's lastValidBlockHeight, so
// manual results should be broadcast promptly.
//
// Native creates carry deterministic x-idempotence-id values. Auto mode retains
// its message-only key; manual mode namespaces its key by mode, chain, and vault.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if s.chain != "" {
		if s.pushMode == PushModeManual {
			return s.signTransactionNativeManual(ctx, tx)
		}
		return s.signTransactionNative(ctx, tx)
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

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are
// swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	actx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
	defer cancel()
	if _, err := s.fetchVault(actx); err != nil {
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
			PushMode: PushModeAuto,
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

// signTransactionNativeManual asks Fordefi to modify and sign tx without
// broadcasting. The caller's transaction is replaced only after the returned
// wire transaction has passed every validation step.
func (s *Signer) signTransactionNativeManual(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if err := s.validateNativeManualInput(tx); err != nil {
		return core.SignedTransaction{}, err
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize transaction message", err)
	}
	idempotencyInput := append(
		[]byte("fordefi:solana:manual:"+string(s.chain)+":"+s.vaultID+":"),
		messageBytes...,
	)
	txID, err := s.submitTransaction(ctx, transactionRequest{
		VaultID:    s.vaultID,
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
	}, core.IdempotencyKeyFromMessage(idempotencyInput), false)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return s.finishNativeManual(ctx, txID, tx)
}

// validateNativeManualInput enforces Fordefi-first signing before any request
// reaches the provider.
func (s *Signer) validateNativeManualInput(tx *solana.Transaction) error {
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	if numRequired < 1 || len(tx.Message.AccountKeys) < numRequired || tx.Message.AccountKeys[0] != s.pubkey {
		return core.NewSignerError(core.CodeSigningFailed,
			"Fordefi native manual signing requires the configured vault to be the transaction fee payer")
	}
	for _, signature := range tx.Signatures {
		if !signature.IsZero() {
			return core.NewSignerError(core.CodeSigningFailed,
				"Fordefi native manual signing must run before any transaction signatures are applied")
		}
	}
	return nil
}

// finishNativeManual validates Fordefi's candidate replacement transaction,
// then atomically transfers it to the caller and returns its canonical wire form.
func (s *Signer) finishNativeManual(ctx context.Context, txID string, original *solana.Transaction) (core.SignedTransaction, error) {
	result, err := s.pollForResult(ctx, txID, false)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if result.RawTransaction == "" {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi manual solana_transaction response missing raw_transaction")
	}
	wireBytes, err := base64.StdEncoding.Strict().DecodeString(result.RawTransaction)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to decode Fordefi manual raw_transaction base64", err)
	}
	if len(wireBytes) > solanaPacketDataSize {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSerializationError,
			"Fordefi manual wire transaction exceeds the Solana size limit")
	}
	returned, err := solana.TransactionFromBytes(wireBytes)
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to deserialize Fordefi manual wire transaction", err)
	}

	numRequired := int(original.Message.Header.NumRequiredSignatures)
	returnedRequired := int(returned.Message.Header.NumRequiredSignatures)
	if returnedRequired != numRequired || len(original.Message.AccountKeys) < numRequired ||
		len(returned.Message.AccountKeys) < returnedRequired {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi manual signing changed the transaction required-signer set")
	}
	for i := 0; i < numRequired; i++ {
		if returned.Message.AccountKeys[i] != original.Message.AccountKeys[i] {
			return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
				"Fordefi manual signing changed the transaction required-signer set")
		}
	}
	if err := s.validateManualMessageMutation(original, returned); err != nil {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi manual signing returned an unauthorized transaction mutation: "+err.Error())
	}
	if len(returned.Signatures) != numRequired {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi manual wire transaction has an invalid signature-slot count")
	}
	signature := returned.Signatures[0]
	if signature.IsZero() {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Fordefi manual wire transaction did not contain the configured vault signature")
	}
	for i := 1; i < len(returned.Signatures); i++ {
		if !returned.Signatures[i].IsZero() {
			return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
				"Fordefi manual signing unexpectedly populated a downstream signer slot")
		}
	}
	returnedMessage, err := returned.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Fordefi-returned manual transaction message", err)
	}
	if !core.VerifyEd25519(s.pubkey, returnedMessage, signature) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed against Fordefi-returned manual message")
	}
	canonicalWire, err := returned.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize Fordefi-returned manual wire transaction", err)
	}
	if len(canonicalWire) > solanaPacketDataSize {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSerializationError,
			"Fordefi manual wire transaction exceeds the Solana size limit")
	}
	encoded := base64.StdEncoding.EncodeToString(canonicalWire)
	*original = *returned
	return core.Classify(original, encoded, signature), nil
}
