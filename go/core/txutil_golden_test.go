package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// goldenSigner is a tiny in-package signer so this golden test does not import the
// memory backend (which would create a core->memory test dependency). It reproduces
// the memory signing path: sign the message bytes, place the signature, serialize.
type goldenSigner struct {
	priv ed25519.PrivateKey
	pub  solana.PublicKey
}

func newGoldenSigner() goldenSigner {
	priv := testPrivateKey()
	var pub solana.PublicKey
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return goldenSigner{priv: priv, pub: pub}
}

// TestGoldenSerialization pins the exact wire bytes of a signed transaction
// built from the deterministic testutils keypair and test transaction. These
// vectors are frozen; if an assertion fails, serialization has drifted from
// the Solana wire format. Never regenerate the vectors to make the suite pass.
func TestGoldenSerialization(t *testing.T) {
	const (
		wantMessageB64  = "AQABA3m1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkIVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAQICAAEMAgAAAEBCDwAAAAAA"
		wantSignedTxB64 = "AQUSPyADYLJarC6XLNhwmO1ZNP7/MECEKnIrOtFcIShPQX3yXWFNn9ftJEhqvrA0W01eyrBk8Pojgs+jRn23Nw4BAAEDebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQhUvjRm3kdJEUyQuFfLqtst8/6e2pe0wCXlg4GmIHbEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkBAgIAAQwCAAAAQEIPAAAAAAA="
		wantPubkey      = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"
	)

	gs := newGoldenSigner()
	tx, err := createTestTransaction(gs.pub)
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
