export interface UtilaSignerConfig {
    apiBaseUrl?: string;
    designatedSigners?: readonly string[];
    maxPollAttempts?: number;
    network: string;
    pollIntervalMs?: number;
    serviceAccountEmail: string;
    serviceAccountPrivateKeyPem: string;
    vaultId: string;
    walletId: string;
}

export interface UtilaWalletResponse {
    wallet?: {
        solanaDetails?: {
            address?: string;
        };
    };
}

export interface UtilaInitiateTransactionRequest {
    designatedSigners?: readonly string[];
    details: {
        solanaSerializedTransaction: {
            network: string;
            publish: false;
            rawTransaction: string;
            replaceBlockhash: false;
            tryReplaceBlockhash: false;
        };
    };
}

export interface UtilaTransactionEnvelope {
    transaction?: UtilaTransaction;
}

export type UtilaTransactionState =
    | 'AWAITING_AML_POLICY_CHECK'
    | 'AWAITING_APPROVAL'
    | 'AWAITING_POLICY_CHECK'
    | 'AWAITING_PUBLISH'
    | 'AWAITING_SIGNATURE'
    | 'CANCELED'
    | 'CONFIRMED'
    | 'DECLINED_BY_AML_POLICY'
    | 'DECLINED'
    | 'DROPPED'
    | 'EXPIRED'
    | 'FAILED'
    | 'MINED_FAILED'
    | 'MINED'
    | 'PUBLISHED'
    | 'REPLACED'
    | 'SIGNED';

export interface UtilaTransaction {
    name?: string;
    solanaTransaction?: {
        rawTransaction?: string;
    };
    state?: UtilaTransactionState;
}
