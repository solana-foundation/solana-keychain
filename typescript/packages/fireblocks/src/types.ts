/**
 * Configuration for creating a FireblocksSigner
 */
export interface FireblocksSignerConfig {
    /** API base URL (default: "https://api.fireblocks.io") */
    apiBaseUrl?: string;

    /** Fireblocks API key (used in X-API-Key header) */
    apiKey: string;

    /** Asset ID (default: "SOL", use "SOL_TEST" for devnet) */
    assetId?: string;

    /** Maximum polling attempts (default: 60) */
    maxPollAttempts?: number;

    /** Polling interval in milliseconds (default: 1000) */
    pollIntervalMs?: number;

    /** RSA 4096 private key in PEM format for JWT signing */
    privateKeyPem: string;

    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;

    /**
     * @deprecated Unsupported and slated for removal. Setting this to `true` is
     * rejected at construction with a `CONFIG_ERROR`; omit it (RAW signing is
     * always used).
     *
     * Fireblocks PROGRAM_CALL signing broadcasts the transaction on-chain and
     * only returns a broadcast transaction id, not a reusable signer-bound
     * signature over the local message bytes. That violates the `SolanaSigner`
     * contract and risks duplicate spends, so the signer always uses RAW signing
     * (signs message bytes only; the caller broadcasts).
     *
     * The field key is retained for now so existing callers passing `true` get a
     * clear error instead of silently different behavior; it will be removed in a
     * future major version.
     */
    useProgramCall?: boolean;

    /** Fireblocks vault account ID */
    vaultAccountId: string;
}

/**
 * Request to create a signing transaction in Fireblocks
 */
export interface CreateTransactionRequest {
    assetId: string;
    extraParameters: RawExtraParameters;
    operation: 'RAW';
    source: TransactionSource;
}

export interface TransactionSource {
    id: string;
    type: string;
}

/**
 * Extra parameters for RAW signing operation
 */
export interface RawExtraParameters {
    rawMessageData: RawMessageData;
}

export interface RawMessageData {
    messages: RawMessage[];
}

export interface RawMessage {
    content: string;
}

/**
 * Response from creating a transaction
 */
export interface CreateTransactionResponse {
    id: string;
    status: string;
}

/**
 * Response from getting a transaction (used for polling)
 */
export interface TransactionResponse {
    id: string;
    signedMessages?: SignedMessage[];
    status: string;
}

export interface SignedMessage {
    signature: SignatureData;
}

export interface SignatureData {
    fullSig: string;
}

/**
 * Response from getting vault account addresses
 */
export interface VaultAddressesResponse {
    addresses: VaultAddress[];
}

export interface VaultAddress {
    address: string;
}

/**
 * Fireblocks transaction status values
 */
export const FireblocksTransactionStatus = {
    BLOCKED: 'BLOCKED',
    BROADCASTING: 'BROADCASTING',
    CANCELLED: 'CANCELLED',
    COMPLETED: 'COMPLETED',
    CONFIRMING: 'CONFIRMING',
    FAILED: 'FAILED',
    PENDING_3RD_PARTY: 'PENDING_3RD_PARTY',
    PENDING_3RD_PARTY_MANUAL_APPROVAL: 'PENDING_3RD_PARTY_MANUAL_APPROVAL',
    PENDING_AUTHORIZATION: 'PENDING_AUTHORIZATION',
    PENDING_SIGNATURE: 'PENDING_SIGNATURE',
    QUEUED: 'QUEUED',
    REJECTED: 'REJECTED',
    SUBMITTED: 'SUBMITTED',
} as const;
export type FireblocksTransactionStatus =
    (typeof FireblocksTransactionStatus)[keyof typeof FireblocksTransactionStatus];

/**
 * Check whether a Fireblocks transaction has reached a terminal state (polling should stop).
 *
 * Replaces the previously exported `TERMINAL_STATUSES` Set, which was removed
 * because module-level `Set` allocation is a side effect that prevents tree-shaking.
 */
export function isTerminalStatus(status: string): boolean {
    return (
        status === FireblocksTransactionStatus.COMPLETED ||
        status === FireblocksTransactionStatus.CANCELLED ||
        status === FireblocksTransactionStatus.REJECTED ||
        status === FireblocksTransactionStatus.BLOCKED ||
        status === FireblocksTransactionStatus.FAILED
    );
}
