//go:build integration

package fordefi

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

// integrationSigner builds a black-box signer against the live Fordefi API
// configured by the environment, run by `just go-test-integration` (loads
// .env) or CI with Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := New(context.Background(), Config{
		AccessToken:   testutils.RequireEnv(t, "FORDEFI_ACCESS_TOKEN"),
		VaultID:       testutils.RequireEnv(t, "FORDEFI_BB_VAULT_ID"),
		PublicKey:     testutils.RequireEnv(t, "FORDEFI_BB_PUBLIC_KEY"),
		PrivateKeyPEM: testutils.RequireEnv(t, "FORDEFI_PRIVATE_KEY_PEM"),
		APIBaseURL:    os.Getenv("FORDEFI_API_BASE_URL"),
	})
	if err != nil {
		t.Fatalf("failed to create fordefi signer: %v", err)
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
