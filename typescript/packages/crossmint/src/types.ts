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
    /** Server signer secret (`xmsk1_<64hex>`). When set, automatically signs awaiting-approval transactions. */
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
    submitted?: Array<{
        signature?: string;
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
