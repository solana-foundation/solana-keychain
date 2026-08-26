package testutils

import (
	"context"

	"github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"
)

// GetLatestBlockhash fetches the latest finalized blockhash from rpcURL, used by
// integration tests whose backend validates the blockhash server-side.
func GetLatestBlockhash(ctx context.Context, rpcURL string) (solana.Hash, error) {
	out, err := rpc.New(rpcURL).GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return solana.Hash{}, err
	}
	return out.Value.Blockhash, nil
}
