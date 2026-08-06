package testutils

import (
	"context"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// GetLatestBlockhash fetches the latest finalized blockhash from rpcURL — the
// Go analog of the Rust tests' rpc_util::get_rpc_blockhash, used by
// integration tests whose backend validates the blockhash server-side.
func GetLatestBlockhash(ctx context.Context, rpcURL string) (solana.Hash, error) {
	out, err := rpc.New(rpcURL).GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return solana.Hash{}, err
	}
	return out.Value.Blockhash, nil
}
