package utila

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
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

	apiBaseURL, err := core.NormalizeHTTPSBaseURL(cfg.APIBaseURL, DefaultAPIBaseURL, "api_base_url")
	if err != nil {
		return nil, err
	}

	pollInterval, maxPollAttempts, err := core.ResolvePollBounds(
		cfg.PollInterval, DefaultPollInterval, cfg.MaxPollAttempts, DefaultMaxPollAttempts)
	if err != nil {
		return nil, err
	}

	signingKey, err := parseSigningKey(cfg.ServiceAccountPrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	client := core.ResolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientConfig)

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
		return core.SignedTransaction{}, core.NewNotInitializedError("utila")
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

	return core.AttachSignature(tx, s.pubkey, sig)
}

// IsAvailable reports whether the Utila wallet can be fetched within the
// availability timeout. Errors are swallowed.
func (s *Signer) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, core.AvailabilityTimeout)
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
			if err := core.SleepContext(ctx, s.pollInterval); err != nil {
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
		return utilaTransaction{}, core.PollTimeoutError("utila", s.maxPollAttempts)
	}
}

// terminalStateError builds the SigningFailed error for a terminal-failure
// state, carrying the wire-format state name.
func terminalStateError(state transactionState) error {
	return core.NewSignerError(core.CodeSigningFailed,
		"Utila transaction reached terminal state "+string(state))
}

// extractSignatureFromRawTransaction decodes the base64 wire transaction Utila
// returned and extracts this wallet's signature, verified against the locally
// requested message.
func (s *Signer) extractSignatureFromRawTransaction(rawTransaction string, expectedMessage []byte) (solana.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(rawTransaction)
	if err != nil {
		return solana.Signature{}, core.WrapSignerError(core.CodeSerializationError,
			"Failed to decode Utila rawTransaction as base64", err)
	}
	return core.ExtractAndVerifyReturnedSignature(raw, s.pubkey, expectedMessage, "Utila")
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
