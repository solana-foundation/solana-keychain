import { type Address, lamports } from '@solana/kit';
import { FailedTransactionMetadata, LiteSVM } from 'litesvm';

export { LiteSVM };

type SimulateResult = ReturnType<LiteSVM['simulateTransaction']>;
type SimError = ReturnType<FailedTransactionMetadata['err']>;

const DEFAULT_AIRDROP = 10_000_000_000n;

/**
 * Airdrops lamports to an address in the test environment
 */
export function airdropLamports(litesvm: LiteSVM, address: Address, amount: bigint = DEFAULT_AIRDROP): void {
    const result = litesvm.airdrop(address, lamports(amount));
    if (result == null) {
        throw new Error(`Airdrop to ${address} failed: returned null`);
    }
    if (result instanceof FailedTransactionMetadata) {
        throw new Error(`Airdrop to ${address} failed: ${String(result.err())}`);
    }
}

/**
 * Formats simulation result for display
 */
export function formatSimulationResult(result: SimulateResult): {
    computeUnits?: bigint;
    error?: SimError;
    logs: string[];
    success: boolean;
} {
    if (result instanceof FailedTransactionMetadata) {
        return {
            error: result.err(),
            logs: result.meta().logs() ?? [],
            success: false,
        };
    }
    return {
        computeUnits: result.meta().computeUnitsConsumed(),
        logs: result.meta().logs() ?? [],
        success: true,
    };
}

/**
 * Truncates an address for display
 */
export function truncateAddress(address: string, prefixLen = 4, suffixLen = 4): string {
    return `${address.slice(0, prefixLen)}...${address.slice(-suffixLen)}`;
}
