package core

import (
	"crypto/ed25519"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// signedReturnedTxBytes builds the deterministic test transaction, signs its
// message with the test key, and returns the signed wire bytes together with
// the message bytes the signature covers.
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
	// Tamper with the message the signature must cover.
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
