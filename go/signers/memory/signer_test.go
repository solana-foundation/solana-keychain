package memory

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/core"
	"github.com/solana-foundation/solana-keychain/go/testutils"
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
