//go:build integration

package cdp

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// integrationSigner builds a signer against the live CDP API configured by
// the environment, via `just go-test-integration` (loads .env) or CI with
// Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := New(Config{
		APIKeyID:     testutils.RequireEnv(t, "CDP_API_KEY_ID"),
		APIKeySecret: testutils.RequireEnv(t, "CDP_API_KEY_SECRET"),
		WalletSecret: testutils.RequireEnv(t, "CDP_WALLET_SECRET"),
		Address:      testutils.RequireEnv(t, "CDP_SOLANA_ADDRESS"),
	})
	if err != nil {
		t.Fatalf("failed to create cdp signer: %v", err)
	}
	return s
}

// CDP's signMessage endpoint only accepts UTF-8 payloads, so this signs a
// literal string rather than raw transaction bytes.
func TestIntegrationSignMessage(t *testing.T) {
	s := integrationSigner(t)
	msg := []byte("CDP keychain test")
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
