package core

import (
	"context"
	"time"

	"github.com/solana-foundation/solana-go/v2"
	"golang.org/x/sync/errgroup"
)

// BatchOptions tunes the batch signing helpers.
type BatchOptions struct {
	// MaxConcurrency bounds how many sign calls run at once. Zero means unbounded
	// (all at once).
	MaxConcurrency int
	// RequestDelay staggers task i by i*RequestDelay before it starts, to respect
	// remote rate limits.
	RequestDelay time.Duration
}

// SignMessages signs each message with s concurrently, preserving order. The first
// error cancels the remaining work and is returned. The core signer methods stay
// single-item; this helper provides the batch shape.
func SignMessages(ctx context.Context, s SolanaSigner, messages [][]byte, opts BatchOptions) ([]solana.Signature, error) {
	out := make([]solana.Signature, len(messages))
	g, ctx := errgroup.WithContext(ctx)
	if opts.MaxConcurrency > 0 {
		g.SetLimit(opts.MaxConcurrency)
	}
	start := time.Now()
	for i := range messages {
		g.Go(func() error {
			if err := stagger(ctx, start, i, opts.RequestDelay); err != nil {
				return err
			}
			sig, err := s.SignMessage(ctx, messages[i])
			if err != nil {
				return err
			}
			out[i] = sig
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// BatchServerSideEffects is implemented by a TransactionSigner whose
// SignTransaction leaves a provider-side request the caller may have to
// reconcile, even though the signing itself is local-verifiable. Such a signer
// is batched one transaction at a time.
type BatchServerSideEffects interface {
	// HasServerSideEffects reports whether the signer's current mode creates a
	// provider-side request per transaction.
	HasServerSideEffects() bool
}

// SignTransactions signs each transaction with s concurrently, preserving order.
// See SignMessages for error and concurrency semantics. Only a TransactionSigner
// can be batched: for a SendingSigner the single nil, err result would hide which
// transactions the provider already executed.
//
// A signer reporting server-side effects through BatchServerSideEffects is signed
// sequentially instead, and a failure returns the transactions completed before it
// alongside the error rather than discarding them.
func SignTransactions(ctx context.Context, s TransactionSigner, txs []*solana.Transaction, opts BatchOptions) ([]SignedTransaction, error) {
	if effectful, ok := s.(BatchServerSideEffects); ok && effectful.HasServerSideEffects() {
		return signTransactionsSequential(ctx, s, txs, opts)
	}

	out := make([]SignedTransaction, len(txs))
	g, ctx := errgroup.WithContext(ctx)
	if opts.MaxConcurrency > 0 {
		g.SetLimit(opts.MaxConcurrency)
	}
	start := time.Now()
	for i := range txs {
		g.Go(func() error {
			if err := stagger(ctx, start, i, opts.RequestDelay); err != nil {
				return err
			}
			signed, err := s.SignTransaction(ctx, txs[i])
			if err != nil {
				return err
			}
			out[i] = signed
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// signTransactionsSequential signs one transaction at a time, stopping at the
// first error. The transactions completed before it are returned with the error:
// each one left a provider-side request, so discarding them would hide work the
// caller has to reconcile.
func signTransactionsSequential(ctx context.Context, s TransactionSigner, txs []*solana.Transaction, opts BatchOptions) ([]SignedTransaction, error) {
	out := make([]SignedTransaction, 0, len(txs))
	start := time.Now()
	for i := range txs {
		if err := stagger(ctx, start, i, opts.RequestDelay); err != nil {
			return out, err
		}
		signed, err := s.SignTransaction(ctx, txs[i])
		if err != nil {
			return out, err
		}
		out = append(out, signed)
	}
	return out, nil
}

// stagger delays task index until start+index*delay (respecting ctx), pacing
// requests for rate limiting. The target is anchored to the
// batch start rather than to when the task acquires a concurrency slot: with
// MaxConcurrency set, slot waits already provide the pacing, and adding a full
// index*delay on top would compound into minutes on large batches — long past
// blockhash expiry. A task whose target time has already passed starts at once.
func stagger(ctx context.Context, start time.Time, index int, delay time.Duration) error {
	if delay <= 0 || index == 0 {
		return nil
	}
	wait := time.Until(start.Add(time.Duration(index) * delay))
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		// Wrap so batch callers always receive a *SignerError (the underlying
		// context error stays reachable via errors.Is/Unwrap), consistent with
		// the backend polling cancellation sites.
		return WrapSignerError(CodeHTTPError, "batch signing cancelled", ctx.Err())
	case <-timer.C:
		return nil
	}
}
