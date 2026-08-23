//go:build integration

package fordefi

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// integrationSigner builds a black-box signer against the live Fordefi API
// configured by the environment, run by `just go-test-integration` (loads
// .env) or CI with Doppler secrets.
func integrationSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := New(context.Background(), Config{
		AccessToken:   requireEnv(t, "FORDEFI_ACCESS_TOKEN"),
		VaultID:       requireEnv(t, "FORDEFI_BB_VAULT_ID"),
		PublicKey:     requireEnv(t, "FORDEFI_BB_PUBLIC_KEY"),
		PrivateKeyPEM: requireEnv(t, "FORDEFI_PRIVATE_KEY_PEM"),
		APIBaseURL:    os.Getenv("FORDEFI_API_BASE_URL"),
	})
	if err != nil {
		t.Fatalf("failed to create fordefi signer: %v", err)
	}
	return s
}

// integrationNativeManualSigner builds a manual native signer when the regular
// Solana Fordefi vault credentials are present. Unlike the black-box integration
// helper, this is optional so developers with only black-box credentials can
// still run the integration suite.
func integrationNativeManualSigner(t *testing.T) *Signer {
	t.Helper()
	required := []string{
		"FORDEFI_ACCESS_TOKEN",
		"FORDEFI_VAULT_ID",
		"FORDEFI_PUBLIC_KEY",
		"FORDEFI_PRIVATE_KEY_PEM",
	}
	for _, key := range required {
		if os.Getenv(key) == "" {
			t.Skipf("%s is not set; skipping Fordefi native-manual integration test", key)
		}
	}
	chain := Chain(os.Getenv("FORDEFI_CHAIN"))
	if chain == "" {
		chain = ChainSolanaDevnet
	}
	if chain != ChainSolanaDevnet && chain != ChainSolanaMainnet {
		t.Fatalf("FORDEFI_CHAIN must be solana_devnet or solana_mainnet, got %q", chain)
	}
	s, err := New(context.Background(), Config{
		AccessToken:     os.Getenv("FORDEFI_ACCESS_TOKEN"),
		VaultID:         os.Getenv("FORDEFI_VAULT_ID"),
		PublicKey:       os.Getenv("FORDEFI_PUBLIC_KEY"),
		PrivateKeyPEM:   os.Getenv("FORDEFI_PRIVATE_KEY_PEM"),
		APIBaseURL:      os.Getenv("FORDEFI_API_BASE_URL"),
		PollInterval:    time.Second,
		MaxPollAttempts: 110,
		Chain:           chain,
		PushMode:        PushModeManual,
	})
	if err != nil {
		t.Fatalf("failed to create native-manual fordefi signer: %v", err)
	}
	return s
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s must be set for integration tests", key)
	}
	return v
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

func TestIntegrationSignTransactionNativeManualWithoutBroadcast(t *testing.T) {
	s := integrationNativeManualSigner(t)
	if s.BroadcastsTransactions() {
		t.Fatal("native manual signer must not report broadcasting")
	}
	pubkey := s.Pubkey()
	instruction := system.NewTransferInstruction(0, pubkey, pubkey).Build()
	tx, err := solana.NewTransaction(
		[]solana.Instruction{instruction},
		solana.Hash{},
		solana.TransactionPayer(pubkey),
	)
	if err != nil {
		t.Fatal(err)
	}
	originalMessage := cloneManualMessage(tx.Message)
	result, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignTransaction native manual: %v", err)
	}
	if result.EncodedTransaction == "" {
		t.Fatal("native manual signing must return the transaction for caller broadcasting")
	}
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !core.VerifyEd25519(pubkey, message, result.Signature) {
		t.Error("native manual signature must verify against Fordefi's returned message")
	}
	decoded, err := solana.TransactionFromBase64(result.EncodedTransaction)
	if err != nil {
		t.Fatalf("decode native manual result: %v", err)
	}
	gotWire, err := decoded.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wantWire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotWire, wantWire) {
		t.Error("encoded manual result must match the caller's replaced transaction")
	}
	originalNormalized, _, err := normalizeManualFeeMessage(originalMessage)
	if err != nil {
		t.Fatalf("normalize original manual message: %v", err)
	}
	returnedNormalized, _, err := normalizeManualFeeMessage(tx.Message)
	if err != nil {
		t.Fatalf("normalize returned manual message: %v", err)
	}
	returnedNormalized.RecentBlockhash = originalNormalized.RecentBlockhash
	originalNormalizedBytes, err := originalNormalized.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	returnedNormalizedBytes, err := returnedNormalized.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalNormalizedBytes, returnedNormalizedBytes) {
		t.Error("live Fordefi mutation must be limited to blockhash and permitted fee instructions")
	}

	// Intentionally no RPC submission: caller-managed broadcasting is the
	// behavior this integration test verifies.
}

func TestIntegrationIsAvailable(t *testing.T) {
	s := integrationSigner(t)
	if !s.IsAvailable(context.Background()) {
		t.Error("signer must be available")
	}
}
