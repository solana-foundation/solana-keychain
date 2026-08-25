//go:build integration

package utila

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// integrationSigner builds a signer against the live Utila API configured by
// the environment; run by `just go-test-integration` (loads .env) or CI with
// Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	cfg := Config{
		ServiceAccountEmail:         testutils.RequireEnv(t, "UTILA_SERVICE_ACCOUNT_EMAIL"),
		ServiceAccountPrivateKeyPEM: testutils.RequireEnv(t, "UTILA_SERVICE_ACCOUNT_PRIVATE_KEY"),
		VaultID:                     testutils.RequireEnv(t, "UTILA_VAULT_ID"),
		WalletID:                    testutils.RequireEnv(t, "UTILA_WALLET_ID"),
		Network:                     testutils.RequireEnv(t, "UTILA_NETWORK"),
		APIBaseURL:                  os.Getenv("UTILA_API_BASE_URL"),
	}
	if ms, err := strconv.Atoi(os.Getenv("UTILA_POLL_INTERVAL_MS")); err == nil {
		cfg.PollInterval = time.Duration(ms) * time.Millisecond
	}
	if attempts, err := strconv.Atoi(os.Getenv("UTILA_MAX_POLL_ATTEMPTS")); err == nil {
		cfg.MaxPollAttempts = attempts
	}
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to create utila signer: %v", err)
	}
	return s
}

func TestIntegrationSignMessageNotSupported(t *testing.T) {
	s := integrationSigner(t)
	if _, err := s.SignMessage(context.Background(), []byte("utila-test")); err == nil {
		t.Error("SignMessage should be unsupported")
	}
}

// Signs a minimal empty-instruction transaction with a real blockhash — the
// backend validates the transaction server-side before signing.
func TestIntegrationSignTransaction(t *testing.T) {
	s := integrationSigner(t)

	rpcURL := os.Getenv("SOLANA_RPC_URL")
	if rpcURL == "" {
		rpcURL = "https://api.devnet.solana.com"
	}
	blockhash, err := testutils.GetLatestBlockhash(context.Background(), rpcURL)
	if err != nil {
		t.Fatalf("failed to fetch latest RPC blockhash: %v", err)
	}

	tx := &solana.Transaction{
		Message: solana.Message{
			Header:          solana.MessageHeader{NumRequiredSignatures: 1},
			AccountKeys:     []solana.PublicKey{s.Pubkey()},
			RecentBlockhash: blockhash,
		},
	}

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	if res.Signature.IsZero() {
		t.Error("signature must not be zero")
	}
}

func TestIntegrationIsAvailable(t *testing.T) {
	s := integrationSigner(t)
	if !s.IsAvailable(context.Background()) {
		t.Error("signer must be available")
	}
}
