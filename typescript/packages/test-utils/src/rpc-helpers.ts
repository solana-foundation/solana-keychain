import type { Blockhash, Slot } from '@solana/kit';

export interface BlockhashWithExpiryBlockHeight {
    blockhash: Blockhash;
    lastValidBlockHeight: Slot;
}

/**
 * Fetch latest blockhash from a real Solana RPC endpoint
 * Used for integration tests that need real network blockhash (e.g., PROGRAM_CALL signers)
 */
export async function getRpcBlockhash(rpcUrl: string): Promise<BlockhashWithExpiryBlockHeight> {
    const response = await fetch(rpcUrl, {
        body: JSON.stringify({
            id: 1,
            jsonrpc: '2.0',
            method: 'getLatestBlockhash',
            params: [],
        }),
        headers: {
            'Content-Type': 'application/json',
        },
        method: 'POST',
    });

    if (!response.ok) {
        throw new Error(`RPC request failed: ${response.status}`);
    }

    const json = (await response.json()) as {
        error?: { message: string };
        result?: {
            value?: {
                blockhash?: string;
                lastValidBlockHeight?: number;
            };
        };
    };

    if (json.error) {
        throw new Error(`RPC error: ${json.error.message}`);
    }

    const blockhash = json.result?.value?.blockhash;
    const lastValidBlockHeight = json.result?.value?.lastValidBlockHeight;

    if (!blockhash || lastValidBlockHeight === undefined) {
        throw new Error('Failed to get blockhash from RPC response');
    }

    return {
        blockhash: blockhash as Blockhash,
        lastValidBlockHeight: BigInt(lastValidBlockHeight),
    };
}
