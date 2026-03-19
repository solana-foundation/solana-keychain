export interface CrossmintSignerConfig {
    apiBaseUrl?: string;
    apiKey: string;
    maxPollAttempts?: number;
    pollIntervalMs?: number;
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
        signer?: unknown;
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
