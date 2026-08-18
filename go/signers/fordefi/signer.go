package fordefi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Timeouts for the two bounded probes (vault ownership verification during New
// and the IsAvailable readiness check).
const (
	vaultVerificationTimeout = 10 * time.Second
	availabilityTimeout      = 5 * time.Second
)

// Signer signs with a Solana key held in a Fordefi vault. All fields are
// immutable after New, so a Signer is safe for concurrent use.
//
// Two signing modes are supported, selected by Config.Chain:
//   - Black box (default, Chain empty): signs the caller's exact message bytes
//     via black_box_signature; the caller broadcasts the signed transaction.
//   - Native Solana (Chain set): submits solana_transaction requests with
//     push_mode "auto" — Fordefi may replace the blockhash and fees, signs,
//     and broadcasts the transaction itself. See SignTransaction.
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
var _ core.Signer = (*Signer)(nil)

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

	apiBaseURL := cfg.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = DefaultAPIBaseURL
	}
	apiBaseURL = strings.TrimRight(apiBaseURL, "/")
	if !strings.HasPrefix(apiBaseURL, "https://") {
		return nil, core.NewSignerError(core.CodeConfigError, "fordefi api_base_url must use HTTPS")
	}

	pubkey, err := solana.PublicKeyFromBase58(cfg.PublicKey)
	if err != nil {
		return nil, core.WrapSignerError(core.CodeInvalidPublicKey, "invalid Solana public key format", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
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
	if !core.VerifyEd25519(s.pubkey, message, signature) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed - the returned signature does not match the public key")
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
// transaction itself. tx is replaced with the Fordefi-signed transaction and
// the returned EncodedTransaction is empty — the transaction is already
// on-chain, so there is nothing for the caller to send. Only transactions
// whose sole required signer is the configured vault are supported.
//
// Native mode is not retry-safe: any failure after Fordefi accepts the
// submission returns CodeBroadcastUnconfirmed carrying the Fordefi transaction
// id; check that transaction with Fordefi before retrying. Each native create
// carries an x-idempotence-id derived from the message bytes, so retrying the
// exact same bytes cannot create a second Fordefi transaction; a retry built
// with a fresh blockhash is a new transaction.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if s.chain != "" {
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
	if !core.VerifyEd25519(s.pubkey, messageBytes, signature) {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"signature verification failed - the returned signature does not match the public key")
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

// IsAvailable reports whether the vault is reachable with the bearer token and
// the request signer can produce an x-signature value. All errors are
// swallowed and reported as false.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	actx, cancel := context.WithTimeout(ctx, availabilityTimeout)
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
	}, "")
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
	}, "")
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

// idempotenceIDFromMessage derives the x-idempotence-id for a native create:
// a UUID built from the first 16 bytes of SHA-256(message bytes), so retrying
// the same message reuses the same id and Fordefi deduplicates the create
// instead of broadcasting a second transaction.
func idempotenceIDFromMessage(messageBytes []byte) string {
	digest := sha256.Sum256(messageBytes)
	id := digest[:16]
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// signTransactionNative signs tx via the native solana_transaction path.
// Fordefi may modify the transaction (at minimum the blockhash), so the
// signature is verified against the returned message bytes and tx is replaced
// with the returned transaction.
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
	}, idempotenceIDFromMessage(messageBytes))
	if err != nil {
		return core.SignedTransaction{}, err
	}
	// Once the submit is accepted Fordefi is already broadcasting (push_mode
	// "auto"), so any later failure leaves an on-chain outcome this client
	// cannot rule out. Report those as CodeBroadcastUnconfirmed carrying the
	// Fordefi transaction id instead of a generic error a caller might blindly
	// retry into a duplicate spend.
	signed, err := s.finishNativeBroadcast(ctx, tx, txID)
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
func (s *Signer) finishNativeBroadcast(ctx context.Context, tx *solana.Transaction, txID string) (core.SignedTransaction, error) {
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

	*tx = *returned
	return core.Classify(tx, "", signature), nil
}
