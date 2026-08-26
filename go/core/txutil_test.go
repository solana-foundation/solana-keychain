package core

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/solana-foundation/solana-go/v2"
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

func TestV1EnvelopePlacesMessageFirstAndSignaturesLast(t *testing.T) {
	payer := testPublicKey()
	tx, err := createTestV1Transaction(payer)
	if err != nil {
		t.Fatal(err)
	}
	priv := testPrivateKey()
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if messageBytes[0] != 0x81 {
		t.Fatalf("v1 message should open with 0x81, got 0x%02x", messageBytes[0])
	}
	if err := AddSignature(tx, payer, solana.Signature(ed25519.Sign(priv, messageBytes))); err != nil {
		t.Fatal(err)
	}

	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:len(messageBytes)], messageBytes) {
		t.Error("v1 envelope should lead with the message bytes")
	}
	if len(wire) != len(messageBytes)+SignatureLength {
		t.Errorf("v1 envelope should be message + one signature, got %d want %d",
			len(wire), len(messageBytes)+SignatureLength)
	}
}

func TestV1TransactionRoundTripsAndClassifies(t *testing.T) {
	payer := testPublicKey()
	tx, err := createTestV1Transaction(payer)
	if err != nil {
		t.Fatal(err)
	}
	messageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	signature := solana.Signature(ed25519.Sign(testPrivateKey(), messageBytes))

	position, err := SigningPosition(tx, payer)
	if err != nil {
		t.Fatal(err)
	}
	if position != 0 {
		t.Errorf("fee payer should occupy slot 0, got %d", position)
	}
	if err := AddSignature(tx, payer, signature); err != nil {
		t.Fatal(err)
	}
	if !HasAllRequiredSignatures(tx) {
		t.Error("v1 transaction should be fully signed")
	}

	encoded, err := Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := solana.TransactionFromBase64(encoded)
	if err != nil {
		t.Fatalf("v1 transaction should decode: %v", err)
	}
	if got := decoded.Message.GetVersion(); got != solana.MessageVersionV1 {
		t.Errorf("decoded version = %v, want v1", got)
	}
	if decoded.Signatures[0] != signature {
		t.Error("v1 signature should survive the round trip")
	}
	if c := Classify(tx, encoded, signature).Completeness; c != Complete {
		t.Errorf("Classify = %v, want Complete", c)
	}
}
