package core

import (
	"testing"

	"github.com/gagliardetto/solana-go"
)

func TestSerializeRoundTrips(t *testing.T) {
	payer := testPublicKey()
	tx, err := createTestTransaction(payer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := solana.TransactionFromBase64(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Message.Header.NumRequiredSignatures != tx.Message.Header.NumRequiredSignatures {
		t.Errorf("header mismatch after round trip")
	}
	// solana-go's own encoder must agree with core.Serialize.
	if want := tx.MustToBase64(); encoded != want {
		t.Errorf("Serialize disagrees with solana-go ToBase64")
	}
}

func TestSigningPositionAndAddSignature(t *testing.T) {
	payer := testPublicKey()
	tx, err := createTestTransaction(payer)
	if err != nil {
		t.Fatal(err)
	}

	if HasAllRequiredSignatures(tx) {
		t.Error("fresh transaction should not be fully signed")
	}
	pos, err := SigningPosition(tx, payer)
	if err != nil {
		t.Fatal(err)
	}
	if pos != 0 {
		t.Errorf("payer position = %d, want 0", pos)
	}

	var sig solana.Signature
	for i := range sig {
		sig[i] = 1
	}
	if err := AddSignature(tx, payer, sig); err != nil {
		t.Fatal(err)
	}
	if !HasAllRequiredSignatures(tx) {
		t.Error("transaction should be complete after its only required signature is added")
	}
	if tx.Signatures[0] != sig {
		t.Error("signature placed at wrong position")
	}

	encoded, _ := Serialize(tx)
	if res := Classify(tx, encoded, sig); !res.IsComplete() {
		t.Error("Classify should report Complete")
	}
}

func TestSigningPositionNotFound(t *testing.T) {
	payer := testPublicKey()
	tx, _ := createTestTransaction(payer)

	var notSigner solana.PublicKey
	notSigner[0] = 0xFF
	_, err := SigningPosition(tx, notSigner)
	if err == nil {
		t.Fatal("expected error for non-signer pubkey")
	}
	if code, _ := CodeOf(err); code != CodeSigningFailed {
		t.Errorf("got code %s, want SIGNING_FAILED", code)
	}
}

func TestClassifyPartialWhenMultiSig(t *testing.T) {
	payer := testPublicKey()
	tx, _ := createTestTransaction(payer)
	// Force a second required signer that we won't provide.
	tx.Message.Header.NumRequiredSignatures = 2
	tx.Message.AccountKeys = append(solana.PublicKeySlice{tx.Message.AccountKeys[0], func() solana.PublicKey {
		var p solana.PublicKey
		p[0] = 0xAB
		return p
	}()}, tx.Message.AccountKeys[1:]...)

	var sig solana.Signature
	for i := range sig {
		sig[i] = 7
	}
	if err := AddSignature(tx, payer, sig); err != nil {
		t.Fatal(err)
	}
	if HasAllRequiredSignatures(tx) {
		t.Error("should be partial: second required signature is missing")
	}
	encoded, _ := Serialize(tx)
	if res := Classify(tx, encoded, sig); res.IsComplete() {
		t.Error("Classify should report Partial")
	}
}

func TestAssertUnversionedWireTransactionAcceptsLegacyEnvelope(t *testing.T) {
	payer := testPublicKey()
	tx, err := createTestTransaction(payer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertUnversionedWireTransaction("Provider", wire); err != nil {
		t.Fatalf("rejected a legacy envelope: %v", err)
	}
}

func TestAssertUnversionedWireTransactionRejectsV1Envelope(t *testing.T) {
	err := AssertUnversionedWireTransaction("Provider", []byte{0x81, 0x01})
	if err == nil {
		t.Fatal("a 0x81 prefix is a v1 envelope this module cannot verify")
	}
	code, ok := CodeOf(err)
	if !ok || code != CodeSerializationError {
		t.Errorf("want %s, got %s", CodeSerializationError, code)
	}
}

func TestAssertUnversionedWireTransactionIgnoresEmptyBytes(t *testing.T) {
	if err := AssertUnversionedWireTransaction("Provider", nil); err != nil {
		t.Fatalf("empty bytes must defer to the decoder: %v", err)
	}
}
