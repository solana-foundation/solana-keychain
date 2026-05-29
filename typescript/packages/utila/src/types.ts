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
    | 'AWAITING_APPROVAL'
    | 'AWAITING_AML_POLICY_CHECK'
    | 'DECLINED_BY_AML_POLICY'
    | 'AWAITING_POLICY_CHECK'
    | 'AWAITING_SIGNATURE'
    | 'SIGNED'
    | 'AWAITING_PUBLISH'
    | 'PUBLISHED'
    | 'MINED'
    | 'MINED_FAILED'
    | 'FAILED'
    | 'DECLINED'
    | 'REPLACED'
    | 'CANCELED'
    | 'DROPPED'
    | 'CONFIRMED'
    | 'EXPIRED'
    | string;

export interface UtilaTransaction {
    name?: string;
    solanaTransaction?: {
        rawTransaction?: string;
    };
    state?: UtilaTransactionState;
}
