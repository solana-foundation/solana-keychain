package core

import (
	"context"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// sendingSigner is a minimal in-package Signer stub for SignAndSendTransaction
// tests: it records that it signed and returns a configurable result.
type sendingSigner struct {
	broadcasts bool
	signed     SignedTransaction
	signCalls  int
}

func (s *sendingSigner) Pubkey() solana.PublicKey { return solana.PublicKey{} }

func (s *sendingSigner) SignMessage(context.Context, []byte) (solana.Signature, error) {
	return solana.Signature{}, NewSignerError(CodeSigningFailed, "not used in this test")
}

func (s *sendingSigner) SignTransaction(context.Context, *solana.Transaction) (SignedTransaction, error) {
	s.signCalls++
	return s.signed, nil
}

func (s *sendingSigner) IsAvailable(context.Context) bool { return true }

func (s *sendingSigner) BroadcastsTransactions() bool { return s.broadcasts }

func completeSignature(first byte) SignedTransaction {
	var sig solana.Signature
	sig[0] = first
	return SignedTransaction{EncodedTransaction: "encoded", Signature: sig, Completeness: Complete}
}

// A managed-broadcast signer needs no send function: its SignTransaction already
// put the transaction on chain, so its own signature identifies it.
func TestSignAndSendTransactionUsesTheProviderBroadcast(t *testing.T) {
	s := &sendingSigner{broadcasts: true, signed: completeSignature(7)}

	sig, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sig != s.signed.Signature {
		t.Errorf("got signature %v, want the one the provider broadcast %v", sig, s.signed.Signature)
	}
}

func TestSignAndSendTransactionBroadcastsWithTheInjectedSender(t *testing.T) {
	s := &sendingSigner{signed: completeSignature(9)}
	var sent string
	send := func(_ context.Context, encoded string) (solana.Signature, error) {
		sent = encoded
		return s.signed.Signature, nil
	}

	sig, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, send)
	if err != nil {
		t.Fatal(err)
	}
	if sent != "encoded" {
		t.Errorf("sender received %q, want the encoded signed transaction", sent)
	}
	if sig != s.signed.Signature {
		t.Errorf("got signature %v, want %v", sig, s.signed.Signature)
	}
}

// A sign-only signer with no sender must fail before signing: a signature the
// caller cannot broadcast is a wasted remote signing request.
func TestSignAndSendTransactionRequiresASenderBeforeSigning(t *testing.T) {
	s := &sendingSigner{signed: completeSignature(1)}

	_, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if code, ok := CodeOf(err); !ok || code != CodeConfigError {
		t.Errorf("got code %q (ok=%v), want CodeConfigError", code, ok)
	}
	if s.signCalls != 0 {
		t.Errorf("signer called %d times, want 0", s.signCalls)
	}
}

// A partially signed transaction cannot land, so it must not reach the sender.
func TestSignAndSendTransactionRejectsPartialSignatures(t *testing.T) {
	s := &sendingSigner{signed: SignedTransaction{EncodedTransaction: "encoded", Completeness: Partial}}
	sendCalled := false
	send := func(context.Context, string) (solana.Signature, error) {
		sendCalled = true
		return solana.Signature{}, nil
	}

	_, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, send)
	if code, ok := CodeOf(err); !ok || code != CodeSigningFailed {
		t.Errorf("got code %q (ok=%v), want CodeSigningFailed", code, ok)
	}
	if sendCalled {
		t.Error("sender was called with a partially signed transaction")
	}
}
