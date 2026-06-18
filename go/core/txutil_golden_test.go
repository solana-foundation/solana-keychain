package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/solana-keychain/go/testutils"
)

// goldenSigner is a tiny in-package signer so this golden test does not import the
// memory backend (which would create a core->memory test dependency). It reproduces
// the memory signing path: sign the message bytes, place the signature, serialize.
type goldenSigner struct {
	priv ed25519.PrivateKey
	pub  solana.PublicKey
}

func newGoldenSigner() goldenSigner {
	priv := testutils.TestPrivateKey()
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return goldenSigner{priv: priv, pub: pub}
}

// TestGoldenSerialization pins the exact wire bytes of a deterministic signed
// transaction. It is the regression gate for the #1 risk: that Go's
// base64(MarshalBinary(tx)) stays byte-identical to the Rust base64(bincode(tx))
// and TS getBase64EncodedWireTransaction output. The vectors below are produced
// from a fixed keypair + fixed transaction (testutils.CreateTestTransaction); the
// SAME logical transaction built in Rust/TS must yield these exact strings.
func TestGoldenSerialization(t *testing.T) {
	const (
		// base64 of the message bytes that get signed (Rust tx.message_data()).
		wantMessageB64 = "AQABA3m1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkIVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAQICAAEMAgAAAEBCDwAAAAAA"
		// base64 of the fully-signed transaction (Rust base64(bincode(tx))).
		wantSignedTxB64 = "AQUSPyADYLJarC6XLNhwmO1ZNP7/MECEKnIrOtFcIShPQX3yXWFNn9ftJEhqvrA0W01eyrBk8Pojgs+jRn23Nw4BAAEDebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQhUvjRm3kdJEUyQuFfLqtst8/6e2pe0wCXlg4GmIHbEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkBAgIAAQwCAAAAQEIPAAAAAAA="
		// base58 of the deterministic test pubkey.
		wantPubkey = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"
	)

	gs := newGoldenSigner()
	tx, err := testutils.CreateTestTransaction(gs.pub)
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var sig solana.Signature
	copy(sig[:], ed25519.Sign(gs.priv, msgBytes))
	if err := AddSignature(tx, gs.pub, sig); err != nil {
		t.Fatal(err)
	}
	encoded, err := Serialize(tx)
	if err != nil {
		t.Fatal(err)
	}

	gotMsg := base64.StdEncoding.EncodeToString(msgBytes)

	// When the constants are placeholders, log the actual values so they can be
	// pinned (and cross-checked against a Rust/TS-generated vector).
	if wantSignedTxB64 == "REPLACE_SIGNED_TX" {
		t.Logf("PUBKEY      = %s", gs.pub.String())
		t.Logf("MESSAGE_B64 = %s", gotMsg)
		t.Logf("SIGNEDTX_B64= %s", encoded)
		t.Fatal("golden vectors not pinned yet")
	}

	if gs.pub.String() != wantPubkey {
		t.Errorf("pubkey = %s, want %s", gs.pub.String(), wantPubkey)
	}
	if gotMsg != wantMessageB64 {
		t.Errorf("message bytes drift:\n got=%s\nwant=%s", gotMsg, wantMessageB64)
	}
	if encoded != wantSignedTxB64 {
		t.Errorf("signed tx bytes drift:\n got=%s\nwant=%s", encoded, wantSignedTxB64)
	}
	if !VerifyEd25519(gs.pub, msgBytes, sig) {
		t.Error("golden signature must verify")
	}
}
