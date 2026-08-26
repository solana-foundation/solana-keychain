package memory

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/solana-foundation/solana-go/v2"

	"github.com/solana-foundation/solana-keychain/go/core/v2"
	"github.com/solana-foundation/solana-keychain/go/testutils/v2"
)

func u8ArrayString(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = strconv.Itoa(int(v))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestNewRejectsEmptyConfig(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
}

func TestNewRejectsMultipleSources(t *testing.T) {
	_, err := New(Config{PrivateKey: testutils.TestPrivateKey(), PrivateKeyPath: "x"})
	if err == nil {
		t.Fatal("expected error for multiple sources")
	}
	if code, _ := core.CodeOf(err); code != core.CodeConfigError {
		t.Errorf("got %s, want CONFIG_ERROR", code)
	}
}

func TestNewFromVariousSources(t *testing.T) {
	want := testutils.TestPublicKey()
	priv := testutils.TestPrivateKey()
	base58 := solana.PrivateKey(priv).String()
	arr := u8ArrayString(priv)

	dir := t.TempDir()
	file := filepath.Join(dir, "id.json")
	if err := os.WriteFile(file, []byte(arr), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]Config{
		"64-byte key":  {PrivateKey: priv},
		"32-byte seed": {PrivateKey: priv.Seed()},
		"base58":       {PrivateKeyString: base58},
		"u8 array":     {PrivateKeyString: arr},
		"keypair file": {PrivateKeyPath: file},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if s.Pubkey() != want {
				t.Errorf("pubkey = %s, want %s", s.Pubkey(), want)
			}
		})
	}
}

func TestNewFromFileErrorTaxonomy(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file is an IO error", func(t *testing.T) {
		_, err := New(Config{PrivateKeyPath: filepath.Join(dir, "missing.json")})
		if code, _ := core.CodeOf(err); code != core.CodeIOError {
			t.Errorf("got %s, want %s", code, core.CodeIOError)
		}
	})

	t.Run("malformed contents are an invalid key", func(t *testing.T) {
		file := filepath.Join(dir, "garbage.json")
		if err := os.WriteFile(file, []byte("not a keypair"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := New(Config{PrivateKeyPath: file})
		if code, _ := core.CodeOf(err); code != core.CodeInvalidPrivateKey {
			t.Errorf("got %s, want %s", code, core.CodeInvalidPrivateKey)
		}
	})
}

func TestSignMessageVerifies(t *testing.T) {
	s, err := New(Config{PrivateKey: testutils.TestPrivateKey()})
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello solana-keychain")
	sig, err := s.SignMessage(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if !core.VerifyEd25519(s.Pubkey(), msg, sig) {
		t.Error("signature should verify against the signer's pubkey")
	}
	if !s.Pubkey().Verify(msg, sig) {
		t.Error("solana-go Verify should also accept the signature")
	}
}

func TestSignTransactionComplete(t *testing.T) {
	s, err := New(Config{PrivateKey: testutils.TestPrivateKey()})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testutils.CreateTestTransaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsComplete() {
		t.Error("single-signer transaction should be Complete")
	}
	msgBytes, _ := tx.Message.MarshalBinary()
	if !core.VerifyEd25519(s.Pubkey(), msgBytes, res.Signature) {
		t.Error("transaction signature should verify against the message bytes")
	}
	decoded, err := solana.TransactionFromBase64(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Signatures[0] != res.Signature {
		t.Error("encoded transaction signature mismatch at position 0")
	}
	if !s.IsAvailable(context.Background()) {
		t.Error("memory signer should always be available")
	}
}

func TestSignV1Transaction(t *testing.T) {
	s, err := New(Config{PrivateKey: testutils.TestPrivateKey()})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testutils.CreateTestV1Transaction(s.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if msgBytes[0] != 0x81 {
		t.Fatalf("v1 message should open with 0x81, got 0x%02x", msgBytes[0])
	}

	res, err := s.SignTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsComplete() {
		t.Error("single-signer v1 transaction should be Complete")
	}
	if !core.VerifyEd25519(s.Pubkey(), msgBytes, res.Signature) {
		t.Error("v1 signature should verify against the prefixed message bytes")
	}
	wire, err := base64.StdEncoding.DecodeString(res.EncodedTransaction)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:len(msgBytes)], msgBytes) {
		t.Error("v1 envelope should lead with the message bytes")
	}
	if len(wire) != len(msgBytes)+core.SignatureLength {
		t.Errorf("v1 envelope length = %d, want %d", len(wire), len(msgBytes)+core.SignatureLength)
	}
}
