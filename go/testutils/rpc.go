package testutils

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"
)

// confirmPollInterval is the delay between two confirmation polls.
const confirmPollInterval = 2 * time.Second

// GetLatestBlockhash fetches the latest finalized blockhash from rpcURL, used by
// integration tests whose backend validates the blockhash server-side.
func GetLatestBlockhash(ctx context.Context, rpcURL string) (solana.Hash, error) {
	out, err := rpc.New(rpcURL).GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return solana.Hash{}, err
	}
	return out.Value.Blockhash, nil
}

// SendEncodedTransaction broadcasts a base64 wire transaction through rpcURL and
// returns its signature. Preflight simulation is pinned to processed commitment
// because a blockhash stamped seconds ago is not finalized yet, and the default
// finalized preflight rejects such a transaction as BlockhashNotFound.
func SendEncodedTransaction(ctx context.Context, rpcURL, encodedTx string) (solana.Signature, error) {
	return rpc.New(rpcURL).SendEncodedTransactionWithOpts(ctx, encodedTx, rpc.TransactionOpts{
		PreflightCommitment: rpc.CommitmentProcessed,
	})
}

// ConfirmTransaction polls rpcURL until signature reaches confirmed or finalized
// status, or timeout elapses. A non-empty rebroadcastTx is resent between polls
// so a dropped transaction still lands while its blockhash is valid; pass an
// empty string when the provider owns the broadcast.
func ConfirmTransaction(ctx context.Context, rpcURL string, signature solana.Signature, rebroadcastTx string, timeout time.Duration) error {
	client := rpc.New(rpcURL)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		statuses, err := client.GetSignatureStatuses(ctx, true, signature)
		if err != nil && !errors.Is(err, rpc.ErrNotFound) {
			return err
		}
		if err == nil && len(statuses.Value) > 0 && statuses.Value[0] != nil {
			status := statuses.Value[0]
			if status.Err != nil {
				return fmt.Errorf("transaction %s failed on-chain: %v", signature, status.Err)
			}
			if status.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
				status.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
				return nil
			}
		}

		if rebroadcastTx != "" {
			_, _ = SendEncodedTransaction(ctx, rpcURL, rebroadcastTx)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(confirmPollInterval):
		}
	}

	return fmt.Errorf("timed out waiting for confirmation of %s", signature)
}
