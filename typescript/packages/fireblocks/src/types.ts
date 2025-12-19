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
     * Use PROGRAM_CALL operation for signing transactions (default: false)
     * When true, Fireblocks signs and broadcasts the transaction to Solana.
     * When false, uses RAW signing (signs message bytes only, caller broadcasts).
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
    extraParameters: ProgramCallExtraParameters | RawExtraParameters;
    operation: 'PROGRAM_CALL' | 'RAW';
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

/**
 * Extra parameters for PROGRAM_CALL signing operation
 */
export interface ProgramCallExtraParameters {
    programCallData: string;
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
    /** Transaction hash (base58 encoded signature) - populated for PROGRAM_CALL after broadcast */
    txHash?: string;
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
export enum FireblocksTransactionStatus {
    SUBMITTED = 'SUBMITTED',
    QUEUED = 'QUEUED',
    PENDING_SIGNATURE = 'PENDING_SIGNATURE',
    PENDING_AUTHORIZATION = 'PENDING_AUTHORIZATION',
    PENDING_3RD_PARTY_MANUAL_APPROVAL = 'PENDING_3RD_PARTY_MANUAL_APPROVAL',
    PENDING_3RD_PARTY = 'PENDING_3RD_PARTY',
    BROADCASTING = 'BROADCASTING',
    CONFIRMING = 'CONFIRMING',
    COMPLETED = 'COMPLETED',
    CANCELLED = 'CANCELLED',
    REJECTED = 'REJECTED',
    BLOCKED = 'BLOCKED',
    FAILED = 'FAILED',
}

/**
 * Terminal transaction statuses (polling should stop)
 */
export const TERMINAL_STATUSES = new Set([
    FireblocksTransactionStatus.COMPLETED,
    FireblocksTransactionStatus.CANCELLED,
    FireblocksTransactionStatus.REJECTED,
    FireblocksTransactionStatus.BLOCKED,
    FireblocksTransactionStatus.FAILED,
]);
