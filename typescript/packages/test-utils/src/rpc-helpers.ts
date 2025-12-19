import { createSolanaRpc, type Blockhash, type Slot } from '@solana/kit';

export interface BlockhashWithExpiryBlockHeight {
    blockhash: Blockhash;
    lastValidBlockHeight: Slot;
}

/**
 * Fetch latest blockhash from a real Solana RPC endpoint
 * Used for integration tests that need real network blockhash (e.g., PROGRAM_CALL signers)
 */
export async function getRpcBlockhash(rpcUrl: string): Promise<BlockhashWithExpiryBlockHeight> {
    const rpc = createSolanaRpc(rpcUrl);
    try {
        const { value: { blockhash, lastValidBlockHeight } } = await rpc.getLatestBlockhash().send();

        if (!blockhash || lastValidBlockHeight === undefined) {
            throw new Error('Failed to get blockhash from RPC response');
        }
        return {
            blockhash,
            lastValidBlockHeight,
        };
    } catch (error) {
        throw new Error(`Failed to get blockhash from RPC: ${error}`);
    }
}
