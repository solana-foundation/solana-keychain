//go:build integration

package vault

import (
	"context"
	"net/http"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// integrationSigner builds a signer against the live Vault configured by the
// environment, run by `just go-test-integration` against a local
// `vault server -dev` with the shared transit test key restored.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	addr := testutils.RequireEnv(t, "VAULT_ADDR")
	cfg := Config{
		VaultAddr: addr,
		Token:     testutils.RequireEnv(t, "VAULT_TOKEN"),
		KeyName:   testutils.RequireEnv(t, "VAULT_KEY_NAME"),
		Pubkey:    testutils.RequireEnv(t, "VAULT_SIGNER_PUBKEY"),
	}
	// The local dev Vault listens on plain HTTP, so the HTTPS-enforcing default
	// client cannot reach it; supply a plain client (the documented escape hatch).
	cfg.HTTPClient = &http.Client{}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create vault signer: %v", err)
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
		t.Fatalf("failed to sign message with vault: %v", err)
	}
	if !core.VerifyEd25519(s.Pubkey(), msg, sig) {
		t.Error("signature should verify against the signer's pubkey")
	}
}

func TestIntegrationSignTransaction(t *testing.T) {
	s := integrationSigner(t)
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	originalMsg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("failed to sign transaction with vault: %v", err)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	if !core.VerifyEd25519(s.Pubkey(), originalMsg, res.Signature) {
		t.Error("signature should be valid for the transaction message")
	}

	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatalf("failed to decode base64 transaction: %v", err)
	}
	decodedMsg, err := decoded.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(decodedMsg) != string(originalMsg) {
		t.Error("decoded transaction should have the same message")
	}
	if decoded.Signatures[0] != res.Signature {
		t.Error("decoded transaction should carry the signature at position 0")
	}
}

func TestIntegrationAvailability(t *testing.T) {
	s := integrationSigner(t)
	if !s.IsAvailable(context.Background()) {
		t.Error("vault signer should be available")
	}
}
