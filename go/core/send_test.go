package core

import (
	"context"
	"testing"

	"github.com/solana-foundation/solana-go/v2"
)

// baseSigner is a minimal in-package SolanaSigner stub: on its own it carries no
// transaction capability at all.
type baseSigner struct{}

func (baseSigner) Pubkey() solana.PublicKey { return solana.PublicKey{} }

func (baseSigner) SignMessage(context.Context, []byte) (solana.Signature, error) {
	return solana.Signature{}, NewSignerError(CodeSigningFailed, "not used in this test")
}

func (baseSigner) IsAvailable(context.Context) bool { return true }

// transactionSigner records that it signed and returns a configurable result.
type transactionSigner struct {
	baseSigner
	signed    SignedTransaction
	signCalls int
}

func (s *transactionSigner) SignTransaction(context.Context, *solana.Transaction) (SignedTransaction, error) {
	s.signCalls++
	return s.signed, nil
}

// sendingSigner broadcasts through its provider and returns a configurable
// signature.
type sendingSigner struct {
	baseSigner
	signature solana.Signature
}

func (s *sendingSigner) SignAndSendTransaction(context.Context, *solana.Transaction) (solana.Signature, error) {
	return s.signature, nil
}

// modifyingSigner stands in for a provider that rewrites the transaction before
// signing it: it records the call and returns a configurable result.
type modifyingSigner struct {
	baseSigner
	signed      SignedTransaction
	modifyCalls int
}

func (s *modifyingSigner) ModifyAndSignTransaction(context.Context, *solana.Transaction) (SignedTransaction, error) {
	s.modifyCalls++
	return s.signed, nil
}

// bothSigner carries two sign-only entry points at once, to pin down which one
// the router picks.
type bothSigner struct {
	baseSigner
	transaction transactionSigner
	modifying   modifyingSigner
}

func (s *bothSigner) SignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error) {
	return s.transaction.SignTransaction(ctx, tx)
}

func (s *bothSigner) ModifyAndSignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error) {
	return s.modifying.ModifyAndSignTransaction(ctx, tx)
}

func completeSignature(first byte) SignedTransaction {
	var sig solana.Signature
	sig[0] = first
	return SignedTransaction{EncodedTransaction: "encoded", Signature: sig, Completeness: Complete}
}

// A SendingSigner needs no send function: the provider already put the
// transaction on chain.
func TestSignAndSendTransactionUsesTheProviderBroadcast(t *testing.T) {
	s := &sendingSigner{signature: completeSignature(7).Signature}

	sig, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sig != s.signature {
		t.Errorf("got signature %v, want the one the provider broadcast %v", sig, s.signature)
	}
}

// A signer carrying no transaction capability cannot be routed either way, and
// must say so rather than silently doing nothing.
func TestSignAndSendTransactionRejectsASignerWithNoTransactionCapability(t *testing.T) {
	_, err := SignAndSendTransaction(context.Background(), baseSigner{}, &solana.Transaction{}, nil)
	if code, ok := CodeOf(err); !ok || code != CodeSigningFailed {
		t.Errorf("got code %q (ok=%v), want CodeSigningFailed", code, ok)
	}
}

func TestSignAndSendTransactionBroadcastsWithTheInjectedSender(t *testing.T) {
	s := &transactionSigner{signed: completeSignature(9)}
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

// A signature the caller cannot broadcast is a wasted remote signing request.
func TestSignAndSendTransactionRequiresASenderBeforeSigning(t *testing.T) {
	s := &transactionSigner{signed: completeSignature(1)}

	_, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if code, ok := CodeOf(err); !ok || code != CodeConfigError {
		t.Errorf("got code %q (ok=%v), want CodeConfigError", code, ok)
	}
	if s.signCalls != 0 {
		t.Errorf("signer called %d times, want 0", s.signCalls)
	}
}

// The signature a broadcasting provider returns is the only handle on the
// transaction it just put on chain, so an empty one cannot be passed off as one.
func TestSignAndSendTransactionRejectsABroadcastWithoutASignature(t *testing.T) {
	s := &sendingSigner{}

	_, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if code, ok := CodeOf(err); !ok || code != CodeSigningFailed {
		t.Errorf("got code %q (ok=%v), want CodeSigningFailed", code, ok)
	}
}

// A ModifyingSigner does not broadcast either, so the caller's send function
// must put the transaction its provider rewrote on chain.
func TestSignAndSendTransactionBroadcastsWhatAModifyingSignerRewrote(t *testing.T) {
	s := &modifyingSigner{signed: completeSignature(3)}
	s.signed.EncodedTransaction = "rewritten"
	var sent string
	send := func(_ context.Context, encoded string) (solana.Signature, error) {
		sent = encoded
		return s.signed.Signature, nil
	}

	sig, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, send)
	if err != nil {
		t.Fatal(err)
	}
	if s.modifyCalls != 1 {
		t.Errorf("ModifyAndSignTransaction called %d times, want 1", s.modifyCalls)
	}
	if sent != "rewritten" {
		t.Errorf("sender received %q, want the rewritten transaction", sent)
	}
	if sig != s.signed.Signature {
		t.Errorf("got signature %v, want %v", sig, s.signed.Signature)
	}
}

// A modifying signer's remote call is as wasteful to throw away as any other, so
// the missing sender must be caught before it runs.
func TestSignAndSendTransactionRequiresASenderBeforeModifying(t *testing.T) {
	s := &modifyingSigner{signed: completeSignature(4)}

	_, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, nil)
	if code, ok := CodeOf(err); !ok || code != CodeConfigError {
		t.Errorf("got code %q (ok=%v), want CodeConfigError", code, ok)
	}
	if s.modifyCalls != 0 {
		t.Errorf("signer called %d times, want 0", s.modifyCalls)
	}
}

// No backend carries both sign-only entry points, but the routing order has to
// be pinned anyway: signing the caller's own bytes is the narrower contract, so
// it wins over letting the provider rewrite them.
func TestSignAndSendTransactionPrefersSignTransactionOverModifying(t *testing.T) {
	s := &bothSigner{
		transaction: transactionSigner{signed: completeSignature(5)},
		modifying:   modifyingSigner{signed: completeSignature(6)},
	}
	send := func(context.Context, string) (solana.Signature, error) {
		return s.transaction.signed.Signature, nil
	}

	if _, err := SignAndSendTransaction(context.Background(), s, &solana.Transaction{}, send); err != nil {
		t.Fatal(err)
	}
	if s.transaction.signCalls != 1 || s.modifying.modifyCalls != 0 {
		t.Errorf("routed to modify (%d) instead of sign (%d)", s.modifying.modifyCalls, s.transaction.signCalls)
	}
}

// A partially signed transaction cannot land, so it must not reach the sender.
func TestSignAndSendTransactionRejectsPartialSignatures(t *testing.T) {
	s := &transactionSigner{signed: SignedTransaction{EncodedTransaction: "encoded", Completeness: Partial}}
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
