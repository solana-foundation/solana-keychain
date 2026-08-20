package utila

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
)

// Signer signs transactions with a Solana wallet held in a Utila vault:
// transactions are initiated remotely with signing designated to the service
// account, polled until Utila reports them SIGNED, and the wallet's signature
// is extracted from the returned wire transaction and verified locally.
//
// All fields are immutable after New, so a Signer is safe for concurrent use.
type Signer struct {
	serviceAccountEmail string
	signingKey          *rsa.PrivateKey
	vaultID             string
	walletID            string
	network             string
	apiBaseURL          string
	client              *http.Client
	pubkey              solana.PublicKey
	pollInterval        time.Duration
	maxPollAttempts     int
	designatedSigners   []string
}

// Ensure Signer satisfies the core contract at compile time.
var _ core.Signer = (*Signer)(nil)

// New builds a Utila signer and initializes it by fetching the wallet's Solana
// address. The returned signer is ready to use.
func New(ctx context.Context, cfg Config) (*Signer, error) {
	for _, field := range []struct{ name, value string }{
		{"service_account_email", cfg.ServiceAccountEmail},
		{"service_account_private_key_pem", cfg.ServiceAccountPrivateKeyPEM},
		{"vault_id", cfg.VaultID},
		{"wallet_id", cfg.WalletID},
		{"network", cfg.Network},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, core.NewSignerError(core.CodeConfigError, field.name+" must not be empty")
		}
	}

	apiBaseURL, err := normalizeAPIBaseURL(cfg.APIBaseURL)
	if err != nil {
		return nil, err
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

	signingKey, err := parseSigningKey(cfg.ServiceAccountPrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = core.NewHTTPClient(cfg.HTTPClientConfig)
	}

	designatedSigners := cfg.DesignatedSigners
	if designatedSigners == nil {
		designatedSigners = []string{"users/" + cfg.ServiceAccountEmail}
	}

	s := &Signer{
		serviceAccountEmail: cfg.ServiceAccountEmail,
		signingKey:          signingKey,
		vaultID:             strings.TrimPrefix(cfg.VaultID, "vaults/"),
		walletID:            trimWalletID(cfg.WalletID),
		network:             cfg.Network,
		apiBaseURL:          apiBaseURL,
		client:              client,
		pollInterval:        pollInterval,
		maxPollAttempts:     maxPollAttempts,
		designatedSigners:   designatedSigners,
	}

	wallet, err := s.fetchWallet(ctx)
	if err != nil {
		return nil, err
	}
	details := wallet.Wallet.SolanaDetails
	if details == nil {
		return nil, core.NewSignerError(core.CodeInvalidPublicKey,
			"Utila wallet response did not include solanaDetails")
	}
	pubkey, err := solana.PublicKeyFromBase58(*details.Address)
	if err != nil {
		return nil, core.NewSignerError(core.CodeInvalidPublicKey,
			"Invalid Solana address returned by Utila wallet")
	}
	s.pubkey = pubkey
	return s, nil
}

// Pubkey returns the Utila wallet's Solana public key (fetched during New).
func (s *Signer) Pubkey() solana.PublicKey { return s.pubkey }

// String renders the signer without any secret material: only the pubkey,
// vault ID, wallet ID, and network are included.
func (s Signer) String() string {
	return "utila.Signer{pubkey: " + s.pubkey.String() + ", vaultID: " + s.vaultID +
		", walletID: " + s.walletID + ", network: " + s.network + "}"
}

// GoString mirrors String so %#v cannot leak secrets either.
func (s Signer) GoString() string { return s.String() }

// SignMessage is intentionally unsupported: Utila does not expose raw message
// signing for Solana wallets, so this always fails with CodeSigningFailed.
func (s *Signer) SignMessage(_ context.Context, _ []byte) (solana.Signature, error) {
	return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
		"Utila sign_message is not supported for Solana wallets in this signer")
}

// SignTransaction submits tx to Utila, polls it to the SIGNED state, extracts
// and verifies the wallet's signature from the returned wire transaction, and
// adds it to tx.
func (s *Signer) SignTransaction(ctx context.Context, tx *solana.Transaction) (core.SignedTransaction, error) {
	if s.pubkey.IsZero() {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeConfigError,
			"UtilaSigner is not initialized")
	}

	expectedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize transaction message", err)
	}
	serialized, err := tx.MarshalBinary()
	if err != nil {
		return core.SignedTransaction{}, core.WrapSignerError(core.CodeSerializationError,
			"failed to serialize transaction", err)
	}

	initiated, err := s.initiateTransaction(ctx, base64.StdEncoding.EncodeToString(serialized))
	if err != nil {
		return core.SignedTransaction{}, err
	}
	signed, err := s.pollSignedTransaction(ctx, initiated)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	if signed.SolanaTransaction == nil || signed.SolanaTransaction.RawTransaction == nil {
		return core.SignedTransaction{}, core.NewSignerError(core.CodeSigningFailed,
			"Utila signed transaction response missing solanaTransaction.rawTransaction")
	}
	sig, err := s.extractSignatureFromRawTransaction(*signed.SolanaTransaction.RawTransaction, expectedMessage)
	if err != nil {
		return core.SignedTransaction{}, err
	}

	if err := core.AddSignature(tx, s.pubkey, sig); err != nil {
		return core.SignedTransaction{}, err
	}
	encoded, err := core.Serialize(tx)
	if err != nil {
		return core.SignedTransaction{}, err
	}
	return core.Classify(tx, encoded, sig), nil
}

// IsAvailable reports whether the Utila wallet can be fetched within the
// availability timeout. Errors are swallowed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, availabilityTimeout)
	defer cancel()
	_, err := s.fetchWallet(ctx)
	return err == nil
}

// pollSignedTransaction drives an initiated transaction to the SIGNED state:
// SIGNED returns, a terminal-failure state fails signing, anything else waits
// pollInterval and re-fetches, for at most maxPollAttempts iterations before
// the final-state check.
func (s *Signer) pollSignedTransaction(ctx context.Context, transaction utilaTransaction) (utilaTransaction, error) {
	for attempt := 0; attempt < s.maxPollAttempts; attempt++ {
		switch {
		case transaction.State == stateSigned:
			return transaction, nil
		case transaction.State.isTerminalFailure():
			return utilaTransaction{}, terminalStateError(transaction.State)
		default:
			if err := sleepContext(ctx, s.pollInterval); err != nil {
				return utilaTransaction{}, err
			}
			transactionID, err := extractTransactionID(transaction.Name)
			if err != nil {
				return utilaTransaction{}, err
			}
			transaction, err = s.getTransaction(ctx, transactionID)
			if err != nil {
				return utilaTransaction{}, err
			}
		}
	}

	switch {
	case transaction.State == stateSigned:
		return transaction, nil
	case transaction.State.isTerminalFailure():
		return utilaTransaction{}, terminalStateError(transaction.State)
	default:
		return utilaTransaction{}, core.NewSignerError(core.CodeRemoteAPIError,
			fmt.Sprintf("Utila transaction polling timed out after %d attempts", s.maxPollAttempts))
	}
}

// terminalStateError builds the SigningFailed error for a terminal-failure
// state, carrying the wire-format state name.
func terminalStateError(state transactionState) error {
	return core.NewSignerError(core.CodeSigningFailed,
		"Utila transaction reached terminal state "+string(state))
}

// extractSignatureFromRawTransaction decodes the base64 wire transaction Utila
// returned, requires its message bytes to equal the locally requested message,
// locates this wallet's required-signer position, and verifies the signature
// before surfacing it.
func (s *Signer) extractSignatureFromRawTransaction(rawTransaction string, expectedMessage []byte) (solana.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(rawTransaction)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"Failed to decode Utila rawTransaction as base64", err)
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"Failed to deserialize Utila rawTransaction", err)
	}

	remoteMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"Failed to deserialize Utila rawTransaction", err)
	}
	if !bytes.Equal(remoteMessage, expectedMessage) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Utila returned a signed transaction with different message bytes")
	}

	position, err := core.SigningPosition(tx, s.pubkey)
	if err != nil {
		return solana.Signature{}, err
	}
	if position >= len(tx.Signatures) || tx.Signatures[position].IsZero() {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Utila rawTransaction did not contain a signer signature")
	}
	signature := tx.Signatures[position]

	if !core.VerifyEd25519(s.pubkey, expectedMessage, signature) {
		return solana.Signature{}, core.NewSignerError(core.CodeSigningFailed,
			"Signature verification failed for Utila rawTransaction")
	}
	return signature, nil
}

// extractTransactionID returns the trailing segment of a transaction resource
// name ("vaults/{v}/transactions/{id}").
func extractTransactionID(name string) (string, error) {
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	if name == "" {
		return "", core.NewSignerError(core.CodeSerializationError,
			"Utila transaction response missing transaction id")
	}
	return name, nil
}

// trimWalletID reduces a full wallet resource name to the id after the last
// "/wallets/" marker.
func trimWalletID(value string) string {
	const marker = "/wallets/"
	if idx := strings.LastIndex(value, marker); idx >= 0 {
		return value[idx+len(marker):]
	}
	return value
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
