export interface CrossmintSignerConfig {
    apiBaseUrl?: string;
    apiKey: string;
    maxPollAttempts?: number;
    pollIntervalMs?: number;
    /**
     * Delay in ms applied before each transaction after the first. Transactions
     * are signed sequentially (not concurrently) because Crossmint creates and
     * may execute each one server-side, so the wall-clock cost is the sum of the
     * per-transaction delays plus signing time. Default: 0 (no delay).
     */
    requestDelayMs?: number;
    signer?: string;
    /**
     * Server signer secret (`xmsk1_<64hex>`). When set, automatically signs
     * awaiting-approval transactions.
     *
     * Trust boundary: the approval challenge is the message of the transaction
     * Crossmint will execute, which is not derivable from the one submitted because
     * Crossmint rewrites it to sponsor gas. Setting this delegates to Crossmint the
     * choice of what gets approved. The signer confirms after the fact that its
     * approval covers the transaction that executed, not that the transaction
     * matches the caller's intent.
     */
    signerSecret?: string;
    walletLocator: string;
}

export interface CrossmintApiError {
    error?: unknown;
    message?: string;
}

export interface CrossmintWalletResponse {
    address: string;
    chainType: string;
    type: string;
}

export interface CrossmintCreateTransactionRequest {
    params: {
        signer?: string;
        transaction: string;
    };
}

export interface CrossmintTransactionOnChain {
    transaction?: string;
    txId?: string;
}

export interface CrossmintTransactionApprovals {
    pending?: Array<{
        message?: string;
        // The response-side signer is a nested object; the matchable locator
        // string (e.g. `server:<address>`) lives at `signer.locator`.
        signer?: { locator?: string };
    }>;
    /**
     * Approvals Crossmint has already collected. A rewritten transaction's wallet
     * signature appears here rather than in a signature slot of the returned
     * transaction.
     */
    submitted?: Array<{
        signature?: string;
        signer?: { address?: string; locator?: string };
    }>;
}

export type CrossmintTransactionStatus = 'awaiting-approval' | 'failed' | 'pending' | 'success';

export interface CrossmintTransactionResponse {
    approvals?: CrossmintTransactionApprovals;
    chainType?: string;
    error?: unknown;
    id: string;
    onChain?: CrossmintTransactionOnChain;
    status: string;
    walletType?: string;
}
