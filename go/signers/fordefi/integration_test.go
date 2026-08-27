//go:build integration

package fordefi

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

// devnetConfirmTimeout bounds how long a devnet transfer may take to confirm.
const devnetConfirmTimeout = 60 * time.Second

// integrationSigner builds a black-box signer against the live Fordefi API
// configured by the environment, run by `just go-test-integration` (loads
// .env) or CI with Doppler secrets.
func integrationSigner(t *testing.T) *BlackBoxSigner {
	t.Helper()
	s, err := NewBlackBox(context.Background(), Config{
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

// integrationNativeConfig builds the config for the native Solana vault, which
// is a different vault from the black box one.
func integrationNativeConfig(t *testing.T, pushMode PushMode) Config {
	t.Helper()
	return Config{
		AccessToken:   testutils.RequireEnv(t, "FORDEFI_ACCESS_TOKEN"),
		VaultID:       testutils.RequireEnv(t, "FORDEFI_VAULT_ID"),
		PublicKey:     testutils.RequireEnv(t, "FORDEFI_PUBLIC_KEY"),
		PrivateKeyPEM: testutils.RequireEnv(t, "FORDEFI_PRIVATE_KEY_PEM"),
		APIBaseURL:    os.Getenv("FORDEFI_API_BASE_URL"),
		Chain:         Chain(testutils.RequireEnv(t, "FORDEFI_CHAIN")),
		PushMode:      pushMode,
	}
}

func integrationNativeAutoSigner(t *testing.T) *NativeAutoSigner {
	t.Helper()
	s, err := NewNativeAuto(context.Background(), integrationNativeConfig(t, PushModeAuto))
	if err != nil {
		t.Fatalf("failed to create fordefi native auto signer: %v", err)
	}
	return s
}

func integrationNativeManualSigner(t *testing.T) *NativeManualSigner {
	t.Helper()
	s, err := NewNativeManual(context.Background(), integrationNativeConfig(t, PushModeManual))
	if err != nil {
		t.Fatalf("failed to create fordefi native manual signer: %v", err)
	}
	return s
}

func devnetRPCURL() string {
	if url := os.Getenv("SOLANA_RPC_URL"); url != "" {
		return url
	}
	return "https://api.devnet.solana.com"
}

// devnetTransfer builds an unsigned transfer paid for and signed by payer, to
// DEVNET_RECIPIENT when set and back to payer otherwise, carrying a live
// blockhash so the cluster accepts it.
func devnetTransfer(t *testing.T, payer solana.PublicKey, rpcURL string) *solana.Transaction {
	t.Helper()
	recipient := payer
	if configured := os.Getenv("DEVNET_RECIPIENT"); configured != "" {
		parsed, err := solana.PublicKeyFromBase58(configured)
		if err != nil {
			t.Fatalf("DEVNET_RECIPIENT is not a valid public key: %v", err)
		}
		recipient = parsed
	}
	blockhash, err := testutils.GetLatestBlockhash(context.Background(), rpcURL)
	if err != nil {
		t.Fatalf("failed to fetch latest RPC blockhash: %v", err)
	}
	tx, err := testutils.CreateTestTransactionTo(payer, recipient)
	if err != nil {
		t.Fatal(err)
	}
	tx.Message.RecentBlockhash = blockhash
	return tx
}

func TestIntegrationNativeAutoSignAndSendTransaction(t *testing.T) {
	s := integrationNativeAutoSigner(t)
	rpcURL := devnetRPCURL()
	tx := devnetTransfer(t, s.Pubkey(), rpcURL)

	sig, err := s.SignAndSendTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SignAndSendTransaction: %v", err)
	}
	if len(sig) != core.SignatureLength {
		t.Fatalf("signature length = %d, want %d", len(sig), core.SignatureLength)
	}

	if err := testutils.ConfirmTransaction(context.Background(), rpcURL, sig, "", devnetConfirmTimeout); err != nil {
		t.Fatalf("transaction was not confirmed on devnet: %v", err)
	}
}

func TestIntegrationNativeManualSignAndBroadcast(t *testing.T) {
	s := integrationNativeManualSigner(t)
	rpcURL := devnetRPCURL()
	tx := devnetTransfer(t, s.Pubkey(), rpcURL)

	res, err := s.ModifyAndSignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("ModifyAndSignTransaction: %v", err)
	}
	if !res.IsComplete() {
		t.Fatal("a transfer whose only required signer is the vault must come back complete")
	}
	returnedMessage, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !core.VerifyEd25519(s.Pubkey(), returnedMessage, res.Signature) {
		t.Fatal("signature must verify against the message Fordefi returned")
	}

	sig, err := testutils.SendEncodedTransaction(context.Background(), rpcURL, res.EncodedTransaction)
	if err != nil {
		t.Fatalf("failed to broadcast the signed transaction: %v", err)
	}
	if sig != res.Signature {
		t.Errorf("broadcast signature = %s, want %s", sig, res.Signature)
	}

	if err := testutils.ConfirmTransaction(
		context.Background(), rpcURL, sig, res.EncodedTransaction, devnetConfirmTimeout,
	); err != nil {
		t.Fatalf("transaction was not confirmed on devnet: %v", err)
	}
}
