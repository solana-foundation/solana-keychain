package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/solana-foundation/solana-go/v2"
)

func signedReturnedTxBytes(t *testing.T, sign bool) (wire []byte, msg []byte) {
	t.Helper()
	tx, err := createTestTransaction(testPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	msg, err = tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var sig solana.Signature
	if sign {
		copy(sig[:], ed25519.Sign(testPrivateKey(), msg))
	}
	tx.Signatures = []solana.Signature{sig}
	wire, err = tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire, msg
}

func TestExtractAndVerifyReturnedSignatureHappyPath(t *testing.T) {
	wire, msg := signedReturnedTxBytes(t, true)
	sig, err := ExtractAndVerifyReturnedSignature(wire, testPublicKey(), msg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !VerifyEd25519(testPublicKey(), msg, sig) {
		t.Error("returned signature does not verify")
	}
}

func TestExtractAndVerifyReturnedSignaturePubkeyNotASigner(t *testing.T) {
	wire, msg := signedReturnedTxBytes(t, true)
	_, err := ExtractAndVerifyReturnedSignature(wire, testRecipient, msg, "test")
	if code, _ := CodeOf(err); code != CodeSigningFailed {
		t.Fatalf("expected CodeSigningFailed, got %v (err: %v)", code, err)
	}
}

func TestExtractAndVerifyReturnedSignatureAllZeroSignature(t *testing.T) {
	wire, msg := signedReturnedTxBytes(t, false)
	_, err := ExtractAndVerifyReturnedSignature(wire, testPublicKey(), msg, "test")
	if code, _ := CodeOf(err); code != CodeSigningFailed {
		t.Fatalf("expected CodeSigningFailed, got %v (err: %v)", code, err)
	}
}

func TestExtractAndVerifyReturnedSignatureNonVerifying(t *testing.T) {
	wire, msg := signedReturnedTxBytes(t, true)
	tampered := append([]byte{}, msg...)
	tampered[len(tampered)-1] ^= 0xFF
	_, err := ExtractAndVerifyReturnedSignature(wire, testPublicKey(), tampered, "test")
	if code, _ := CodeOf(err); code != CodeSigningFailed {
		t.Fatalf("expected CodeSigningFailed, got %v (err: %v)", code, err)
	}
}

func TestExtractAndVerifyReturnedSignatureMalformedBytes(t *testing.T) {
	_, msg := signedReturnedTxBytes(t, true)
	_, err := ExtractAndVerifyReturnedSignature([]byte{0xFF, 0x01, 0x02}, testPublicKey(), msg, "test")
	if code, _ := CodeOf(err); code != CodeSerializationError {
		t.Fatalf("expected CodeSerializationError, got %v (err: %v)", code, err)
	}
}

func TestPublicKeyFromSPKIDER(t *testing.T) {
	want := testPublicKey()
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, want[:]...)

	got, ok := PublicKeyFromSPKIDER(der)
	if !ok || got != want {
		t.Errorf("PublicKeyFromSPKIDER = %v, %v, want %v, true", got, ok, want)
	}

	foreignOID := append([]byte(nil), der...)
	foreignOID[8] = 0x71
	if _, ok := PublicKeyFromSPKIDER(foreignOID); ok {
		t.Error("a non-Ed25519 algorithm OID must be rejected")
	}
	if _, ok := PublicKeyFromSPKIDER(der[:40]); ok {
		t.Error("a truncated SubjectPublicKeyInfo must be rejected")
	}
}

func TestPublicKeyFromSPKIPEM(t *testing.T) {
	want := testPublicKey()
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, want[:]...)
	pemText := "-----BEGIN PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(der) + "\n-----END PUBLIC KEY-----\n"

	got, ok := PublicKeyFromSPKIPEM(pemText)
	if !ok || got != want {
		t.Errorf("PublicKeyFromSPKIPEM = %v, %v, want %v, true", got, ok, want)
	}
	if _, ok := PublicKeyFromSPKIPEM("not a pem"); ok {
		t.Error("text that is not a PEM key must be rejected")
	}
}

func TestPublicKeyFromRawEd25519(t *testing.T) {
	want := testPublicKey()

	got, ok := PublicKeyFromRawEd25519(want[:])
	if !ok || got != want {
		t.Errorf("PublicKeyFromRawEd25519 = %v, %v, want %v, true", got, ok, want)
	}
	if _, ok := PublicKeyFromRawEd25519(want[:31]); ok {
		t.Error("a key of the wrong length must be rejected")
	}
}
