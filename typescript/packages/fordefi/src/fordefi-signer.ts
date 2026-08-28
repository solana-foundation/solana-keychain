import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';

import { Address, assertIsAddress } from '@solana/addresses';
import { getBase58Encoder, getBase64Decoder, getBase64Encoder, getUtf8Encoder } from '@solana/codecs-strings';
import {
    abortableDelay,
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    idempotencyKeyFromMessage,
    normalizeBaseUrl,
    providerMayHaveAccepted,
    providerStatus,
    signBatchSequential,
    signBatchStaggered,
    SignerError,
    SignerErrorCode,
    SolanaMessageSigner,
    SolanaModifyingSigner,
    SolanaSendingSigner,
    SolanaTransactionSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import {
    MessagePartialSignerConfig,
    SignableMessage,
    SignatureDictionary,
    TransactionModifyingSigner,
    TransactionModifyingSignerConfig,
    TransactionPartialSigner,
    TransactionPartialSignerConfig,
    TransactionSendingSigner,
    TransactionSendingSignerConfig,
} from '@solana/signers';
import { getCompiledTransactionMessageDecoder } from '@solana/transaction-messages';
import {
    assertIsTransactionWithinSizeLimit,
    Base64EncodedWireTransaction,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionLifetimeConstraintFromCompiledTransactionMessage,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type {
    FordefiBlackBoxSignatureRequest,
    FordefiCreateTransactionResponse,
    FordefiPushMode,
    FordefiSolanaFee,
    FordefiSolanaMessageRequest,
    FordefiSolanaTransactionRequest,
    FordefiTransactionStatusResponse,
    FordefiVaultResponse,
    SolanaChainUniqueId,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.fordefi.com';
const DEFAULT_POLL_INTERVAL_MS = 2000;

let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;
let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let utf8Encoder: ReturnType<typeof getUtf8Encoder> | undefined;
const DEFAULT_MAX_POLL_ATTEMPTS = 50;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

// An unrecognized value would otherwise fall through to auto and broadcast.
const PUSH_MODES = new Set<string>(['auto', 'manual']);
/** Terminal success states for pushable transactions (solana_transaction with push_mode auto). */
const PUSHABLE_SUCCESS_STATES = new Set(['completed']);
/** Terminal success states for non-pushable transactions (black_box_signature, solana_message, native manual). */
const NON_PUSHABLE_SUCCESS_STATES = new Set(['signed', 'completed']);
/** Terminal failure states (all transaction types). Mirrors the Rust backend. */
const FAILURE_STATES = new Set([
    'aborted',
    'cancelled',
    'completed_reverted',
    'dropped',
    'error_pushing_to_blockchain',
    'error_signing',
    'insufficient_funds',
    'mined_reverted',
]);

/**
 * Signs Fordefi API-request payloads for the `x-signature` header.
 *
 * Implementations receive the fully-formatted payload (`{path}|{timestamp}|{body}`)
 * and must return the exact base64 value Fordefi expects: base64 of the DER-encoded
 * ECDSA P-256 signature over `SHA-256(payload)`.
 *
 * The built-in PEM path (`privateKeyPem`) signs locally. To keep the request key in
 * a KMS/HSM, implement this interface and pass it as `requestSigner` (e.g. AWS KMS
 * `Sign` with `ECDSA_SHA_256` returns a DER signature — base64-encode it).
 */
export interface FordefiRequestSigner {
    /** Return the base64 `x-signature` value for `payload`. May be async. */
    signRequest(payload: string): Promise<string> | string;
}

/**
 * Built-in {@link FordefiRequestSigner} that signs locally with a PEM-encoded
 * ECDSA P-256 private key.
 */
class PemRequestSigner implements FordefiRequestSigner {
    private readonly privateKey: KeyObject;

    constructor(privateKeyPem: string) {
        this.privateKey = createPrivateKey(privateKeyPem);
    }

    signRequest(payload: string): string {
        const sign = createSign('SHA256').update(payload, 'utf8').end();
        return sign.sign(this.privateKey, 'base64');
    }
}

export interface FordefiSignerConfig {
    /** Fordefi API User bearer token */
    accessToken: string;
    /** Optional API base URL (default: https://api.fordefi.com) */
    apiBaseUrl?: string;
    /**
     * Solana chain identifier. When set, uses native Solana API types
     * (`solana_serialized_transaction_message` for transactions,
     * `solana_message` for messages) instead of `black_box_signature`.
     */
    chain?: SolanaChainUniqueId;
    /** Solana fee configuration for native mode transactions. Only used when `chain` is set. */
    fee?: FordefiSolanaFee;
    /** Positive integer max polling attempts before timeout (default: 50) */
    maxPollAttempts?: number;
    /** Non-negative integer polling interval in ms (default: 2000) */
    pollIntervalMs?: number;
    /**
     * PEM-encoded ECDSA P-256 private key for API request signing.
     * Provide exactly one of `privateKeyPem` or `requestSigner`.
     */
    privateKeyPem?: string;
    /** Solana public key of the vault (base58) */
    publicKey: string;
    /**
     * Whether Fordefi broadcasts a native Solana transaction. Omitted is
     * equivalent to `'auto'`; `'manual'` requires `chain`.
     */
    pushMode?: FordefiPushMode;
    /** Optional delay in ms between concurrent signing requests (default: 0) */
    requestDelayMs?: number;
    /**
     * Custom API-request signer (e.g. a KMS/HSM-backed implementation).
     * Provide exactly one of `privateKeyPem` or `requestSigner`. When set,
     * `privateKeyPem` is ignored.
     */
    requestSigner?: FordefiRequestSigner;
    /**
     * Per-request HTTP timeout in ms applied to every signing-path network
     * call (submit POST and each poll GET). Default: 30000.
     */
    requestTimeoutMs?: number;
    /** Fordefi vault UUID */
    vaultId: string;
}

/**
 * Fordefi signer shape returned when `chain` enables native Solana mode with
 * `pushMode` omitted or `'auto'`.
 *
 * Native auto mode may replace the recent blockhash and fees before signing and
 * broadcasts the result itself, so it must be used through Kit's
 * {@link TransactionSendingSigner} flow rather than as a partial signer.
 * Instances expose no `signTransactions`, because Kit classifies signers by
 * duck-typed method presence, but do sign messages.
 *
 * Native auto mode is not retry-safe: any failure after Fordefi accepts the
 * submission rejects with `BROADCAST_UNCONFIRMED` carrying
 * `context.providerTransactionId`; check that transaction with Fordefi before
 * retrying. A submission that fails without a usable response rejects with
 * `BROADCAST_UNCONFIRMED` carrying any transaction id the failed response
 * named, and none when no response reached the client at all.
 *
 * Each native create carries an `x-idempotence-id` derived from the message
 * bytes, so replaying these exact bytes cannot create a second transaction; a
 * rebuilt transaction derives a different id and is broadcast again.
 */
export interface FordefiNativeSigner<TAddress extends string = string>
    extends SolanaSendingSigner<TAddress>, SolanaMessageSigner<TAddress> {}

/**
 * Fordefi signer shape returned when `chain` is set and `pushMode` is
 * `'manual'`.
 *
 * Fordefi rewrites the message (the recent blockhash, and the Compute Budget
 * fee instructions it manages) and signs it without broadcasting, so
 * `modifyAndSignTransactions()` returns the transaction Fordefi signed rather
 * than signatures for the caller's own bytes. Continue from that transaction
 * and never from the one you submitted: every downstream signer has to sign the
 * message the Fordefi signature covers. What Fordefi changed is not diffed, so
 * inspect the result before broadcasting it.
 *
 * Instances expose neither `signTransactions` nor `signAndSendTransactions`,
 * and Fordefi must be the fee payer and sign before every downstream signer.
 */
export interface FordefiNativeManualSigner<TAddress extends string = string>
    extends SolanaModifyingSigner<TAddress>, SolanaMessageSigner<TAddress> {}

/**
 * Fordefi signer shape returned when `chain` is unset (black box mode).
 *
 * Black box mode signs the caller's exact bytes and never broadcasts, so it
 * is a partial signer for both transactions and messages.
 */
export interface FordefiBlackBoxSigner<TAddress extends string = string>
    extends SolanaTransactionSigner<TAddress>, SolanaMessageSigner<TAddress> {}

/**
 * Create and initialize a Fordefi-backed signer.
 *
 * Construction is synchronous (the configured `publicKey` is the source of
 * truth for the vault address), but the factory keeps its `Promise` return
 * type for parity with the other backends.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode: 'manual' },
): Promise<FordefiNativeManualSigner<TAddress>>;
export function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode?: 'auto' },
): Promise<FordefiNativeSigner<TAddress>>;
export function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain?: undefined },
): Promise<FordefiBlackBoxSigner<TAddress>>;
export function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig,
): Promise<FordefiBlackBoxSigner<TAddress> | FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig,
): Promise<FordefiBlackBoxSigner<TAddress> | FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress>> {
    // The instance's own properties expose the mode-appropriate signing
    // method, which the class type cannot express statically.
    return await Promise.resolve(FordefiSigner.create(config) as unknown as FordefiBlackBoxSigner<TAddress>);
}

/**
 * Fordefi MPC signer using Fordefi's API.
 *
 * Transaction signing is async: submit via POST, poll GET until MPC signing completes.
 * API requests require ECDSA P-256 request-level signing.
 */
class FordefiSigner<TAddress extends string = string> implements SolanaMessageSigner<TAddress> {
    readonly address: Address<TAddress>;
    declare modifyAndSignTransactions?: TransactionModifyingSigner<TAddress>['modifyAndSignTransactions'];
    declare signAndSendTransactions?: TransactionSendingSigner<TAddress>['signAndSendTransactions'];
    declare signTransactions?: TransactionPartialSigner<TAddress>['signTransactions'];
    private readonly accessToken: string;
    private readonly apiBaseUrl: string;
    private readonly chain?: SolanaChainUniqueId;
    private readonly fee?: FordefiSolanaFee;
    private readonly maxPollAttempts: number;
    private readonly pollIntervalMs: number;
    private readonly pushMode: FordefiPushMode;
    private readonly requestSigner: FordefiRequestSigner;
    private readonly requestDelayMs: number;
    private readonly requestTimeoutMs: number;
    private readonly vaultId: string;

    private constructor(config: FordefiSignerConfig, address: Address<TAddress>) {
        this.accessToken = config.accessToken;
        this.apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_BASE_URL);
        this.chain = config.chain;
        this.fee = config.fee;
        this.maxPollAttempts = config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS;
        this.pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        this.pushMode = config.pushMode ?? 'auto';
        this.requestSigner = config.requestSigner ?? new PemRequestSigner(config.privateKeyPem ?? '');
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
        this.vaultId = config.vaultId;
        this.address = address;

        // Kit classifies signers by duck-typed method presence, so each mode
        // exposes exactly the method it can honor as an own property: native
        // manual mode returns a rewritten transaction, native auto mode
        // rewrites and broadcasts it, and black-box mode signs the caller's
        // exact bytes.
        if (this.chain && this.pushMode === 'manual') {
            this.modifyAndSignTransactions = this.modifyAndSignNativeTransactions.bind(this);
        } else if (this.chain) {
            this.signAndSendTransactions = this.signAndSendNativeTransactions.bind(this);
        } else {
            this.signTransactions = this.signBlackBoxTransactions.bind(this);
        }
    }

    /** Create a FordefiSigner with the provided configuration. */
    static create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode: 'manual' },
    ): FordefiNativeManualSigner<TAddress> & FordefiSigner<TAddress>;
    static create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode?: 'auto' },
    ): FordefiNativeSigner<TAddress> & FordefiSigner<TAddress>;
    static create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain?: undefined },
    ): FordefiBlackBoxSigner<TAddress> & FordefiSigner<TAddress>;
    static create<TAddress extends string = string>(
        config: FordefiSignerConfig,
    ): FordefiSigner<TAddress> &
        (FordefiBlackBoxSigner<TAddress> | FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress>);
    static create<TAddress extends string = string>(config: FordefiSignerConfig): FordefiSigner<TAddress> {
        if (!config.accessToken) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'accessToken must not be empty',
            });
        }

        if (!config.vaultId) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'vaultId must not be empty',
            });
        }

        if (!config.publicKey) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'publicKey must not be empty',
            });
        }

        if (config.requestSigner && config.privateKeyPem) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'provide exactly one of privateKeyPem or requestSigner, not both',
            });
        }

        if (!config.requestSigner && !config.privateKeyPem) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'one of privateKeyPem or requestSigner must be provided',
            });
        }

        if (config.pushMode !== undefined && !PUSH_MODES.has(config.pushMode)) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: "pushMode must be 'auto' or 'manual'",
            });
        }

        if (config.pushMode === 'manual' && !config.chain) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: "pushMode 'manual' requires chain to enable Fordefi native Solana mode",
            });
        }

        FordefiSigner.validatePollingConfig(
            config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS,
            config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
        );
        validateRequestDelayMs(config.requestDelayMs ?? 0);
        FordefiSigner.validateRequestTimeoutMs(config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_BASE_URL);
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

        // Validate the PEM key can be parsed (only on the built-in PEM path).
        if (config.privateKeyPem) {
            try {
                createPrivateKey(config.privateKeyPem);
            } catch (error) {
                return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                    cause: error,
                    message: 'Failed to parse privateKeyPem as a valid private key',
                });
            }
        }

        try {
            assertIsAddress(config.publicKey);
        } catch (error) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana public key format',
            });
        }

        // Trusted provider: the configured publicKey is authoritative, so no
        // init-time vault fetch is needed to confirm it.
        return new FordefiSigner<TAddress>(config, config.publicKey as Address<TAddress>);
    }

    /**
     * Lightweight readiness probe.
     *
     * Checks that the bearer token and vault are reachable (GET does not
     * require `x-signature`), then exercises the local P-256 signing path
     * to catch a malformed `privateKeyPem` early. Note: a passing local
     * sign does not guarantee the Fordefi server recognises the
     * corresponding public key — that is only proven on the first real
     * POST signing call.
     */
    async isAvailable(): Promise<boolean> {
        try {
            await this.request<FordefiVaultResponse>('GET', `/api/v1/vaults/${this.vaultId}`, undefined, 5_000);
        } catch {
            return false;
        }

        try {
            await this.signRequest('/api/v1/vaults', Date.now(), '');
        } catch {
            return false;
        }

        return true;
    }

    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const signatureBytes = await this.signMessage(message.content, config?.abortSignal);
                await assertSignatureValid({
                    data: message.content,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Partial-signer path for black-box mode; attached as an own property only
     * when `chain` is unset.
     */
    private async signBlackBoxTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const { sigDict, verificationData } = await this.signBlackBoxTransaction(
                    transaction.messageBytes,
                    config?.abortSignal,
                );
                const signatureBytes = Object.values(sigDict)[0];
                if (!signatureBytes) {
                    return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        address: this.address,
                        message: 'No signature bytes found in extracted signature dictionary',
                    });
                }
                await assertSignatureValid({
                    data: verificationData,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return sigDict;
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Sign an unchanged Solana transaction message through Fordefi's black-box API.
     *
     * The raw Ed25519 signature is valid regardless of this signer's account
     * index, so this path supports multi-signature transactions where Fordefi
     * is not the fee payer.
     */
    private async signBlackBoxTransaction(
        messageBytes: ArrayLike<number>,
        abortSignal?: AbortSignal,
    ): Promise<{ sigDict: SignatureDictionary; verificationData: Uint8Array }> {
        const bytes = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(Array.from(messageBytes));
        base64Decoder ||= getBase64Decoder();
        const base64Data = base64Decoder.decode(bytes);

        const txId = await this.submitBlackBoxSignature(base64Data, abortSignal);
        const result = await this.pollForResult(txId, { pushable: false }, abortSignal);
        const sigBase64 = this.extractSignatureData(result);
        let sigBytes: Uint8Array;
        try {
            base64Encoder ||= getBase64Encoder();
            sigBytes = new Uint8Array(base64Encoder.encode(sigBase64));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi signature base64',
            });
        }
        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected ${ED25519_SIGNATURE_LENGTH}-byte Ed25519 signature, got ${sigBytes.length}`,
            });
        }
        return {
            sigDict: createSignatureDictionary({ signature: sigBytes as SignatureBytes, signerAddress: this.address }),
            verificationData: bytes,
        };
    }

    /**
     * Native manual path for Kit's TransactionModifyingSigner contract; attached
     * as an own property only when `chain` is set and `pushMode` is `'manual'`.
     *
     * Fordefi rewrites the message before signing it and does not broadcast, so
     * the returned transaction replaces the caller's. The rewrite itself is not
     * diffed: the signature is verified against the bytes Fordefi returned, and
     * those bytes are what the caller continues from.
     */
    private async modifyAndSignNativeTransactions(
        transactions: readonly (Transaction | (Transaction & TransactionWithLifetime))[],
        config?: TransactionModifyingSignerConfig,
    ): Promise<readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[]> {
        // Each submit is a Fordefi-side create, so the batch runs one at a time:
        // a concurrent failure would abandon siblings Fordefi has already
        // accepted and signed.
        return await signBatchSequential(
            transactions,
            async transaction => {
                config?.abortSignal?.throwIfAborted();
                this.assertNativeManualTransactionSupported(transaction);

                base64Decoder ||= getBase64Decoder();
                const base64Data = base64Decoder.decode(new Uint8Array(transaction.messageBytes));
                const txId = await this.submitSolanaTransaction(base64Data, 'manual', config?.abortSignal);
                return await this.finishNativeManualSigning(txId, transaction, config?.abortSignal);
            },
            this.requestDelayMs,
            'completedTransactions',
            config?.abortSignal,
        );
    }

    /**
     * Poll a submitted manual transaction to completion, verify the vault's
     * signature against the message Fordefi returned, and hand back those bytes
     * as a Kit transaction the caller can broadcast.
     */
    private async finishNativeManualSigning(
        txId: string,
        originalTransaction: Transaction | (Transaction & TransactionWithLifetime),
        abortSignal?: AbortSignal,
    ): Promise<Transaction & TransactionWithinSizeLimit & TransactionWithLifetime> {
        const result = await this.pollForResult(txId, { pushable: false }, abortSignal);
        if (!result.raw_transaction) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Fordefi solana_transaction response missing raw_transaction',
            });
        }

        let decodedTransaction: Transaction;
        try {
            base64Encoder ||= getBase64Encoder();
            decodedTransaction = getTransactionDecoder().decode(base64Encoder.encode(result.raw_transaction));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode the Fordefi wire transaction',
            });
        }

        const signerSignature = decodedTransaction.signatures[this.address];
        if (!signerSignature) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi wire transaction did not contain the configured vault signature',
            });
        }

        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature: signerSignature,
            signerAddress: this.address,
        });

        const signedTransaction = Object.freeze({
            ...decodedTransaction,
            lifetimeConstraint: await this.readReturnedLifetime(originalTransaction, decodedTransaction),
            signatures: Object.freeze(decodedTransaction.signatures),
        });

        try {
            assertIsTransactionWithinSizeLimit(signedTransaction);
        } catch (error) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Fordefi wire transaction exceeds the Solana transaction size limit',
            });
        }

        abortSignal?.throwIfAborted();
        return signedTransaction;
    }

    /**
     * Recover the lifetime of the returned transaction from its compiled
     * message. Fordefi does not report the `lastValidBlockHeight` of a blockhash
     * it refreshed, so Kit substitutes `U64_MAX`; the caller's own constraint is
     * kept instead whenever the blockhash survived the rewrite. A durable nonce
     * constraint is complete as decoded, so the returned one always wins.
     */
    private async readReturnedLifetime(
        originalTransaction: Transaction | (Transaction & TransactionWithLifetime),
        returnedTransaction: Transaction,
    ): Promise<TransactionWithLifetime['lifetimeConstraint']> {
        let returnedLifetime: TransactionWithLifetime['lifetimeConstraint'];
        try {
            const compiledMessage = getCompiledTransactionMessageDecoder().decode(returnedTransaction.messageBytes);
            returnedLifetime = await getTransactionLifetimeConstraintFromCompiledTransactionMessage(compiledMessage);
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to recover the lifetime of the Fordefi wire transaction',
            });
        }

        if ('lifetimeConstraint' in originalTransaction) {
            const originalLifetime = originalTransaction.lifetimeConstraint;
            const blockhashSurvived =
                'blockhash' in originalLifetime &&
                'blockhash' in returnedLifetime &&
                originalLifetime.blockhash === returnedLifetime.blockhash;
            if (blockhashSurvived) {
                return originalLifetime;
            }
        }

        return returnedLifetime;
    }

    /**
     * Native Solana transaction path for Kit's TransactionSendingSigner contract.
     *
     * Fordefi may replace the message lifetime and fees, then broadcasts the
     * returned transaction itself. The result is therefore the on-chain
     * transaction identifier (the first wire signature), not a signature
     * dictionary to be applied to the caller's original message.
     */
    private async signAndSendNativeTransactions(
        transactions: readonly (Transaction | (Transaction & TransactionWithLifetime))[],
        config?: TransactionSendingSignerConfig,
    ): Promise<readonly SignatureBytes[]> {
        if (!this.chain) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                address: this.address,
                message: 'signAndSendTransactions() requires chain to enable Fordefi native Solana mode',
            });
        }

        // Auto mode broadcasts every accepted submit, so the batch runs one at a
        // time: a concurrent failure would discard both a sibling's unconfirmed
        // transaction id and the signature of one already on chain.
        return await signBatchSequential(
            transactions,
            async transaction => {
                config?.abortSignal?.throwIfAborted();
                this.assertNativeAutoTransactionSupported(transaction);

                base64Decoder ||= getBase64Decoder();
                const base64Data = base64Decoder.decode(new Uint8Array(transaction.messageBytes));
                let txId: string;
                try {
                    txId = await this.submitSolanaTransaction(base64Data, 'auto', config?.abortSignal);
                } catch (error) {
                    if (!providerMayHaveAccepted(error)) {
                        throw error;
                    }
                    // Fordefi may be broadcasting a transaction whose id never reached us.
                    const status = providerStatus(error);
                    const providerTransactionId =
                        error instanceof SignerError ? error.context?.providerTransactionId : undefined;
                    return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        cause: error,
                        message:
                            typeof providerTransactionId === 'string'
                                ? `Fordefi may have accepted the transaction, but the outcome could not be confirmed (provider transaction id: ${providerTransactionId})`
                                : 'Fordefi may have accepted the transaction, but no transaction id was returned',
                        ...(status === undefined ? {} : { status }),
                        ...(typeof providerTransactionId === 'string' ? { providerTransactionId } : {}),
                    });
                }
                // Once the submit is accepted Fordefi is already broadcasting
                // (push_mode 'auto'), so any later failure leaves an on-chain
                // outcome this client cannot rule out. Report those as
                // BROADCAST_UNCONFIRMED carrying the Fordefi transaction id
                // instead of a generic error a caller might blindly retry into
                // a duplicate spend.
                try {
                    return await this.finishNativeBroadcast(txId, config);
                } catch (error) {
                    return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        cause: error,
                        message: `Fordefi may have executed the transaction, but the outcome could not be confirmed (provider transaction id: ${txId})`,
                        providerTransactionId: txId,
                    });
                }
            },
            this.requestDelayMs,
            'completedSignatures',
            config?.abortSignal,
        );
    }

    /**
     * Poll a submitted native transaction to completion and extract and verify
     * the vault's signature from the returned wire bytes.
     */
    private async finishNativeBroadcast(
        txId: string,
        config?: TransactionSendingSignerConfig,
    ): Promise<SignatureBytes> {
        const result = await this.pollForResult(txId, { pushable: true }, config?.abortSignal);
        if (!result.raw_transaction) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Fordefi solana_transaction response missing raw_transaction',
            });
        }

        const signedWireTx = result.raw_transaction as Base64EncodedWireTransaction;
        base64Encoder ||= getBase64Encoder();
        const decodedTransaction = getTransactionDecoder().decode(base64Encoder.encode(signedWireTx));

        const signerSignature = decodedTransaction.signatures[this.address];
        if (!signerSignature) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi wire transaction did not contain the configured vault signature',
            });
        }

        // Kit resolves the fee payer's signature, whichever slot the version puts it in.
        let transactionSignature: SignatureBytes;
        try {
            base58Encoder ||= getBase58Encoder();
            transactionSignature = base58Encoder.encode(
                getSignatureFromTransaction(decodedTransaction),
            ) as SignatureBytes;
        } catch (error) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Fordefi wire transaction carries no fee-payer signature to identify the broadcast by',
            });
        }

        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature: signerSignature,
            signerAddress: this.address,
        });
        config?.abortSignal?.throwIfAborted();
        return transactionSignature;
    }

    /**
     * The current request schema sends only message bytes. Supporting native
     * multi-signer auto-broadcast would also require forwarding all other
     * partial signatures via Fordefi's `details.signatures` field.
     */
    private assertNativeAutoTransactionSupported(transaction: Transaction): void {
        const requiredSignerAddresses = Object.keys(transaction.signatures);
        if (requiredSignerAddresses.length !== 1 || requiredSignerAddresses[0] !== this.address) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message:
                    'Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault',
            });
        }
    }

    /** Fordefi may only rewrite a message the vault pays for and no one has signed yet. */
    private assertNativeManualTransactionSupported(transaction: Transaction): void {
        if (Object.keys(transaction.signatures)[0] !== this.address) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi native manual signing requires the configured vault to be the transaction fee payer',
            });
        }
        if (Object.values(transaction.signatures).some(signature => signature !== null)) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi native manual signing must run before any transaction signatures are applied',
            });
        }
    }

    /**
     * POST a transaction request to Fordefi and return the transaction ID.
     * Shared by all signing modes (black_box, solana_transaction, solana_message).
     */
    private async submitTransaction(
        requestBody: FordefiBlackBoxSignatureRequest | FordefiSolanaMessageRequest | FordefiSolanaTransactionRequest,
        idempotenceId?: string,
        abortSignal?: AbortSignal,
    ): Promise<string> {
        const apiPath = '/api/v1/transactions';
        const createResponse = await this.request<FordefiCreateTransactionResponse>(
            'POST',
            apiPath,
            JSON.stringify(requestBody),
            this.requestTimeoutMs,
            idempotenceId,
            abortSignal,
        );
        if (!createResponse.id) {
            return throwSignerError(SignerErrorCode.SERIALIZATION_ERROR, {
                message: 'Fordefi returned no transaction id',
            });
        }
        return createResponse.id;
    }

    private async submitBlackBoxSignature(base64Data: string, abortSignal?: AbortSignal): Promise<string> {
        const requestBody: FordefiBlackBoxSignatureRequest = {
            details: {
                format: 'hash_binary',
                hash_binary: base64Data,
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'black_box_signature',
            vault_id: this.vaultId,
        };
        return await this.submitTransaction(requestBody, undefined, abortSignal);
    }

    /**
     * Submit a native Solana serialized transaction message for signing, and for
     * broadcasting when `pushMode` is `'auto'`.
     */
    private async submitSolanaTransaction(
        base64Data: string,
        pushMode: FordefiPushMode,
        abortSignal?: AbortSignal,
    ): Promise<string> {
        const requestBody: FordefiSolanaTransactionRequest = {
            details: {
                chain: this.chain!,
                data: base64Data,
                ...(this.fee ? { fee: this.fee } : {}),
                push_mode: pushMode,
                type: 'solana_serialized_transaction_message',
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'solana_transaction',
            vault_id: this.vaultId,
        };
        base64Encoder ||= getBase64Encoder();
        const messageBytes = new Uint8Array(base64Encoder.encode(base64Data));
        return await this.submitTransaction(
            requestBody,
            await idempotencyKeyFromMessage(
                pushMode === 'manual' ? this.namespaceManualIdempotencyInput(messageBytes) : messageBytes,
            ),
            abortSignal,
        );
    }

    /**
     * Namespaced so the same bytes submitted for signing cannot collide with an
     * earlier auto create that did broadcast them.
     */
    private namespaceManualIdempotencyInput(messageBytes: Uint8Array): Uint8Array {
        utf8Encoder ||= getUtf8Encoder();
        const namespace = utf8Encoder.encode(`fordefi:solana:manual:${this.chain!}:${this.vaultId}:`);
        const namespaced = new Uint8Array(namespace.length + messageBytes.length);
        namespaced.set(namespace);
        namespaced.set(messageBytes, namespace.length);
        return namespaced;
    }

    private async submitSolanaMessage(base64Data: string, abortSignal?: AbortSignal): Promise<string> {
        const requestBody: FordefiSolanaMessageRequest = {
            details: {
                chain: this.chain!,
                raw_data: base64Data,
                type: 'personal_message_type',
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'solana_message',
            vault_id: this.vaultId,
        };
        return await this.submitTransaction(requestBody, undefined, abortSignal);
    }

    /**
     * Sign a Solana personal message via Fordefi MPC.
     * Submits the message, polls for completion, and returns the raw 64-byte Ed25519 signature.
     */
    private async signMessage(messageBytes: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        base64Decoder ||= getBase64Decoder();
        const base64Data = base64Decoder.decode(messageBytes);

        const txId = this.chain
            ? await this.submitSolanaMessage(base64Data, abortSignal)
            : await this.submitBlackBoxSignature(base64Data, abortSignal);
        const result = await this.pollForResult(txId, { pushable: false }, abortSignal);
        const sigBase64 = this.extractSignatureData(result);

        let sigBytes: Uint8Array;
        try {
            base64Encoder ||= getBase64Encoder();
            sigBytes = new Uint8Array(base64Encoder.encode(sigBase64));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi signature base64',
            });
        }

        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected ${ED25519_SIGNATURE_LENGTH}-byte Ed25519 signature, got ${sigBytes.length}`,
            });
        }

        return sigBytes as SignatureBytes;
    }

    /**
     * Poll until the transaction reaches a terminal state and return the full response.
     *
     * @param pushable - When `true`, treats pushable success state
     *   `completed` as terminal. When `false`, uses non-pushable states
     *   (`signed`, `completed`).
     */
    private async pollForResult(
        txId: string,
        { pushable }: { pushable: boolean },
        abortSignal?: AbortSignal,
    ): Promise<FordefiTransactionStatusResponse> {
        const successStates = pushable ? PUSHABLE_SUCCESS_STATES : NON_PUSHABLE_SUCCESS_STATES;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const txData = await this.request<FordefiTransactionStatusResponse>(
                'GET',
                `/api/v1/transactions/${txId}`,
                undefined,
                undefined,
                undefined,
                abortSignal,
            );

            if (successStates.has(txData.state)) {
                return txData;
            }

            if (FAILURE_STATES.has(txData.state)) {
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Transaction ${txId} reached terminal state: ${txData.state}`,
                });
            }

            if (attempt + 1 < this.maxPollAttempts) {
                await abortableDelay(this.pollIntervalMs, abortSignal);
            }
        }

        return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Polling timeout after ${this.maxPollAttempts} attempts`,
            providerTransactionId: txId,
        });
    }

    private extractSignatureData(result: FordefiTransactionStatusResponse): string {
        const sigData = result.signatures?.[0]?.data;
        if (!sigData) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Transaction signed but no signatures in response',
            });
        }
        return sigData;
    }

    /**
     * Sign an API request payload via the configured {@link FordefiRequestSigner}.
     * Payload format: `{path}|{timestamp}|{body}`
     */
    private async signRequest(path: string, timestamp: number, body: string): Promise<string> {
        const payload = `${path}|${timestamp}|${body}`;
        return await this.requestSigner.signRequest(payload);
    }

    private async request<T>(
        method: 'GET' | 'POST',
        apiPath: string,
        body?: string,
        timeoutMs = this.requestTimeoutMs,
        idempotenceId?: string,
        abortSignal?: AbortSignal,
    ): Promise<T> {
        const headers: Record<string, string> = {
            Authorization: `Bearer ${this.accessToken}`,
        };
        if (body !== undefined) {
            const timestamp = Date.now();
            headers['Content-Type'] = 'application/json';
            headers['x-signature'] = await this.signRequest(apiPath, timestamp, body);
            headers['x-timestamp'] = timestamp.toString();
        }
        if (idempotenceId !== undefined) {
            headers['x-idempotence-id'] = idempotenceId;
        }

        return await fetchSignerJson<T>({
            abortSignal,
            init: { body, headers, method },
            providerName: 'Fordefi',
            timeoutMs,
            url: `${this.apiBaseUrl}${apiPath}`,
        });
    }

    private static validatePollingConfig(maxPollAttempts: number, pollIntervalMs: number): void {
        if (!Number.isSafeInteger(maxPollAttempts) || maxPollAttempts < 1) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'maxPollAttempts must be a positive integer',
            });
        }
        if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'pollIntervalMs must be a non-negative integer',
            });
        }
    }

    private static validateRequestTimeoutMs(requestTimeoutMs: number): void {
        if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestTimeoutMs must be a positive finite number',
            });
        }
    }
}
