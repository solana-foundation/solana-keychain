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
     * Sign transactions with the PROGRAM_CALL operation instead of RAW (default: `false`).
     *
     * PROGRAM_CALL is sent with `signOnly: true` and `useDurableNonce: false`, so
     * Fireblocks signs the submitted transaction without broadcasting it and
     * without rewriting the message. The returned signature is verified against
     * the vault address over the local message bytes before it is used, and the
     * caller broadcasts as in RAW mode. `signMessages()` always uses RAW, since
     * PROGRAM_CALL only accepts serialized transactions.
     *
     * PROGRAM_CALL accepts legacy and v0 messages only, requires a hot wallet,
     * and must be enabled for the workspace by Fireblocks.
     */
    useProgramCall?: boolean;

    /** Fireblocks vault account ID */
    vaultAccountId: string;
}

/**
 * Request to create a signing transaction in Fireblocks
 */
export type CreateTransactionRequest = CreateProgramCallTransactionRequest | CreateRawTransactionRequest;

export interface CreateRawTransactionRequest {
    assetId: string;
    extraParameters: RawExtraParameters;
    operation: 'RAW';
    source: TransactionSource;
}

export interface CreateProgramCallTransactionRequest {
    assetId: string;
    /** Message-derived id Fireblocks uses to deduplicate PROGRAM_CALL creates. */
    externalTxId: string;
    extraParameters: ProgramCallExtraParameters;
    operation: 'PROGRAM_CALL';
    source: TransactionSource;
}

/**
 * Extra parameters for PROGRAM_CALL signing.
 *
 * `useDurableNonce` defaults to `true` on the Fireblocks side, which prepends an
 * `AdvanceNonce` instruction to the submitted message; the signature would then
 * cover different bytes than the caller's transaction.
 */
export interface ProgramCallExtraParameters {
    programCallData: string;
    signOnly: boolean;
    useDurableNonce: boolean;
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
    assetId?: string;
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
    SIGNED: 'SIGNED',
    SUBMITTED: 'SUBMITTED',
} as const;
export type FireblocksTransactionStatus =
    (typeof FireblocksTransactionStatus)[keyof typeof FireblocksTransactionStatus];

/**
 * Check whether a Fireblocks transaction has reached a terminal state (polling should stop).
 *
 * Keep this a function: a module-level `Set` of terminal statuses is a
 * side-effectful allocation that breaks tree-shaking.
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
