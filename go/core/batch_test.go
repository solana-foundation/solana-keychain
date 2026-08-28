package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solana-foundation/solana-go/v2"
)

// countingSigner is a minimal in-package TransactionSigner stub for batch tests:
// it records how many sign calls it received and returns a signature derived from
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
	c.calls.Add(1)
	return SignedTransaction{}, nil
}

func (c *countingSigner) IsAvailable(context.Context) bool { return true }

// Only a TransactionSigner can be batched; the parameter type is what keeps a
// SendingSigner out, where the single nil, err result would hide which
// transactions the provider already executed.
func TestSignTransactionsSignsEveryTransaction(t *testing.T) {
	s := &countingSigner{}
	out, err := SignTransactions(context.Background(), s, []*solana.Transaction{{}, {}}, BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || s.calls.Load() != 2 {
		t.Errorf("got %d results and %d calls, want 2 and 2", len(out), s.calls.Load())
	}
}

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

// effectfulSigner reports server-side effects, records the order of its calls,
// and fails the transaction whose message names failAt.
type effectfulSigner struct {
	countingSigner
	failAt   byte
	signed   []byte
	inFlight atomic.Int32
	maxSeen  atomic.Int32
}

func (e *effectfulSigner) HasServerSideEffects() bool { return true }

func (e *effectfulSigner) SignTransaction(_ context.Context, tx *solana.Transaction) (SignedTransaction, error) {
	if seen := e.inFlight.Add(1); seen > e.maxSeen.Load() {
		e.maxSeen.Store(seen)
	}
	defer e.inFlight.Add(-1)

	var marker byte
	if len(tx.Message.AccountKeys) > 0 {
		marker = tx.Message.AccountKeys[0][0]
	}
	if marker == e.failAt {
		return SignedTransaction{}, NewSignerError(CodeBroadcastUnconfirmed, "unresolved")
	}
	e.signed = append(e.signed, marker)
	return SignedTransaction{}, nil
}

// A signer with server-side effects is batched one transaction at a time, and a
// failure returns the transactions completed before it: each left a provider-side
// request the caller has to reconcile, so discarding them would hide that work.
func TestSignTransactionsSerializesASignerWithServerSideEffects(t *testing.T) {
	markedTx := func(marker byte) *solana.Transaction {
		return &solana.Transaction{
			Message: solana.Message{AccountKeys: []solana.PublicKey{{marker}}},
		}
	}

	s := &effectfulSigner{failAt: 2}
	out, err := SignTransactions(context.Background(), s,
		[]*solana.Transaction{markedTx(1), markedTx(2), markedTx(3)}, BatchOptions{})

	if code, _ := CodeOf(err); code != CodeBroadcastUnconfirmed {
		t.Fatalf("got %s, want BROADCAST_UNCONFIRMED", code)
	}
	if len(out) != 1 {
		t.Errorf("got %d completed transactions, want the one signed before the failure", len(out))
	}
	if string(s.signed) != string([]byte{1}) {
		t.Errorf("signed %v, want only the transaction before the failure", s.signed)
	}
	if got := s.maxSeen.Load(); got != 1 {
		t.Errorf("max concurrent sign calls = %d, want 1", got)
	}
}
