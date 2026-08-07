package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
)

// countingSigner is a minimal in-package Signer stub for batch tests: it
// records how many sign calls it received and returns a signature derived from
// the message's first byte so ordering can be asserted.
type countingSigner struct {
	calls atomic.Int32
}

func (c *countingSigner) Pubkey() solana.PublicKey { return solana.PublicKey{} }

func (c *countingSigner) SignMessage(_ context.Context, message []byte) (solana.Signature, error) {
	c.calls.Add(1)
	var sig solana.Signature
	if len(message) > 0 {
		sig[0] = message[0]
	}
	return sig, nil
}

func (c *countingSigner) SignTransaction(context.Context, *solana.Transaction) (SignedTransaction, error) {
	return SignedTransaction{}, NewSignerError(CodeSigningFailed, "not used in this test")
}

func (c *countingSigner) IsAvailable(context.Context) bool { return true }

func TestSignMessagesPreservesOrder(t *testing.T) {
	s := &countingSigner{}
	messages := [][]byte{{10}, {20}, {30}, {40}}
	sigs, err := SignMessages(context.Background(), s, messages, BatchOptions{MaxConcurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != len(messages) {
		t.Fatalf("got %d signatures, want %d", len(sigs), len(messages))
	}
	for i, msg := range messages {
		if sigs[i][0] != msg[0] {
			t.Errorf("signature %d out of order: got marker %d, want %d", i, sigs[i][0], msg[0])
		}
	}
	if got := s.calls.Load(); got != int32(len(messages)) {
		t.Errorf("signer called %d times, want %d", got, len(messages))
	}
}

// TestStaggerCancellationReturnsSignerError guards the *SignerError contract:
// a context cancelled during the stagger delay must surface as a coded
// SignerError (with the context error reachable via errors.Is), not as a raw
// context.Canceled.
func TestStaggerCancellationReturnsSignerError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := &countingSigner{}
	_, err := SignMessages(ctx, s, [][]byte{{1}, {2}}, BatchOptions{RequestDelay: time.Hour})
	if err == nil {
		t.Fatal("expected error from cancelled batch")
	}
	if code, ok := CodeOf(err); !ok || code != CodeHTTPError {
		t.Errorf("got code %q (ok=%v), want CodeHTTPError", code, ok)
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("underlying context.Canceled should remain reachable via errors.Is")
	}
}

// TestStaggerAnchorsToBatchStart pins the stagger semantics: the delay target is
// start+index*delay measured from the batch start, so a task whose slot opened
// after its target time (e.g. behind a slow task with MaxConcurrency set) starts
// immediately instead of compounding another index*delay of sleep.
func TestStaggerAnchorsToBatchStart(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	done := make(chan error, 1)
	go func() { done <- stagger(context.Background(), start, 5, time.Minute) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stagger slept relative to slot acquisition instead of batch start")
	}
}
