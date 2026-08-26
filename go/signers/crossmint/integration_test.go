//go:build integration

package crossmint

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

// integrationSigner builds a signer against the live Crossmint API configured
// by the environment, via `just go-test-integration` (loads .env) or CI with
// Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := New(context.Background(), Config{
		APIKey:        testutils.RequireEnv(t, "CROSSMINT_API_KEY"),
		WalletLocator: testutils.RequireEnv(t, "CROSSMINT_WALLET_LOCATOR"),
		SignerSecret:  os.Getenv("CROSSMINT_SIGNER_SECRET"),
		Signer:        os.Getenv("CROSSMINT_SIGNER"),
		APIBaseURL:    os.Getenv("CROSSMINT_API_BASE_URL"),
	})
	if err != nil {
		t.Fatalf("failed to create crossmint signer: %v", err)
	}
	return s
}

func TestIntegrationSignMessageNotSupported(t *testing.T) {
	s := integrationSigner(t)
	_, err := s.SignMessage(context.Background(), []byte("crossmint-test"))
	if err == nil {
		t.Fatal("SignMessage should be unsupported")
	}
	var se *core.SignerError
	if !errors.As(err, &se) || se.Code != core.CodeSigningFailed {
		t.Errorf("expected CodeSigningFailed, got %v", err)
	}
	if !strings.Contains(se.Detail(), "not supported") {
		t.Errorf("expected not-supported detail, got %s", se.Detail())
	}
}

// Signs a minimal empty-instruction transaction with a real blockhash: the
// backend validates and finalizes the transaction server-side, so this stays
// focused on remote signing behavior rather than balance/program execution.
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
	if len(res.Signature) != core.SignatureLength {
		t.Fatalf("signature length = %d, want %d", len(res.Signature), core.SignatureLength)
	}
	// Crossmint sponsors gas, so it rewrites the transaction, signs its own bytes
	// and broadcasts server-side. The signature identifies what it landed and
	// there is nothing left for the caller to send.
	if res.EncodedTransaction != "" {
		t.Error("a Crossmint-broadcast transaction leaves nothing for the caller to send")
	}
	for _, sig := range tx.Signatures {
		if !sig.IsZero() {
			t.Error("the caller's transaction must not carry a signature over other bytes")
		}
	}
}

func TestIntegrationIsAvailable(t *testing.T) {
	s := integrationSigner(t)
	if !s.IsAvailable(context.Background()) {
		t.Error("signer must be available")
	}
}
