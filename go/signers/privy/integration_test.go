//go:build integration

package privy

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// integrationSigner builds a signer against the live Privy API configured by
// the environment, run by `just go-test-integration` (loads .env) or CI with
// Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	cfg := Config{
		AppID:      testutils.RequireEnv(t, "PRIVY_APP_ID"),
		AppSecret:  testutils.RequireEnv(t, "PRIVY_APP_SECRET"),
		WalletID:   testutils.RequireEnv(t, "PRIVY_WALLET_ID"),
		APIBaseURL: os.Getenv("PRIVY_API_BASE_URL"),
	}
	if key := os.Getenv("PRIVY_AUTHORIZATION_PRIVATE_KEY"); key != "" {
		cfg.AuthorizationContext = &AuthorizationContext{AuthorizationPrivateKeys: []string{key}}
	}
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to create privy signer: %v", err)
	}
	return s
}

func TestIntegrationSignMessage(t *testing.T) {
	s := integrationSigner(t)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if !core.VerifyEd25519(s.Pubkey(), msg, sig) {
		t.Error("signature must verify against the signer pubkey")
	}
}

// There are no LiteSVM bindings for Go, so verification is cryptographic only.
func TestIntegrationSignTransaction(t *testing.T) {
	s := integrationSigner(t)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	originalMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	if !core.VerifyEd25519(s.Pubkey(), originalMessage, res.Signature) {
		t.Error("signature must verify against the signed message")
	}
	raw, err := base64.StdEncoding.DecodeString(res.EncodedTransaction)
	if err != nil {
		t.Fatalf("encoded transaction is not valid base64: %v", err)
	}
	decoded, err := solana.TransactionFromBytes(raw)
	if err != nil {
		t.Fatalf("failed to decode signed transaction: %v", err)
	}
	roundTripped, err := decoded.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTripped, originalMessage) {
		t.Error("decoded transaction message must equal the original message")
	}
}

func TestIntegrationIsAvailable(t *testing.T) {
	s := integrationSigner(t)
	if !s.IsAvailable(context.Background()) {
		t.Error("signer must be available")
	}
}
