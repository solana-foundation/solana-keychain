import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';

import { Address, assertIsAddress } from '@solana/addresses';
import { getBase58Decoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    extractSignatureFromWireTransaction,
    fetchSignerJson,
    normalizeBaseUrl,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import {
    SignableMessage,
    SignatureDictionary,
    TransactionSendingSigner,
    TransactionSendingSignerConfig,
} from '@solana/signers';
import {
    Base64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type {
    FordefiBlackBoxSignatureRequest,
    FordefiCreateTransactionResponse,
    FordefiSolanaFee,
    FordefiSolanaMessageRequest,
    FordefiSolanaTransactionRequest,
    FordefiTransactionStatusResponse,
    FordefiVaultResponse,
    SolanaChainUniqueId,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.fordefi.com';
const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_MAX_POLL_ATTEMPTS = 50;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** Terminal success states for pushable transactions (solana_transaction with push_mode auto). */
const PUSHABLE_SUCCESS_STATES = new Set(['completed']);
/** Terminal success states for non-pushable transactions (black_box_signature, solana_message). */
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
     * (`solana_serialized_transaction_message` with `push_mode: 'auto'` for
     * transactions, `solana_message` for messages) instead of `black_box_signature`.
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
 * Fordefi signer shape returned when `chain` enables native Solana mode.
 *
 * Native mode may replace the recent blockhash and fees before signing and
 * broadcasts with `push_mode: 'auto'`, so it must be used through Kit's
 * {@link TransactionSendingSigner} flow rather than as a partial signer.
 */
export interface FordefiNativeSigner<TAddress extends string = string>
    extends SolanaSigner<TAddress>, TransactionSendingSigner<TAddress> {}

/**
 * Create and initialize a Fordefi-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain: SolanaChainUniqueId },
): Promise<FordefiNativeSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig,
): Promise<SolanaSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await FordefiSigner.create(config);
}

/**
 * Fordefi MPC signer using Fordefi's API.
 *
 * Transaction signing is async: submit via POST, poll GET until MPC signing completes.
 * API requests require ECDSA P-256 request-level signing.
 *
 * Prefer `createFordefiSigner()`. Class export will be removed in a future version.
 */
export class FordefiSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    declare signAndSendTransactions?: TransactionSendingSigner<TAddress>['signAndSendTransactions'];
    private readonly accessToken: string;
    private readonly apiBaseUrl: string;
    private readonly chain?: SolanaChainUniqueId;
    private readonly fee?: FordefiSolanaFee;
    private readonly maxPollAttempts: number;
    private readonly pollIntervalMs: number;
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
        this.requestSigner = config.requestSigner ?? new PemRequestSigner(config.privateKeyPem ?? '');
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
        this.vaultId = config.vaultId;
        this.address = address;

        // Keep this method off black-box instances so Kit does not misclassify
        // them as sending signers. Native instances expose it as an own property.
        if (this.chain) {
            this.signAndSendTransactions = this.signAndSendNativeTransactions.bind(this);
        }
    }

    /**
     * Create a FordefiSigner with the provided configuration.
     */
    static async create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain: SolanaChainUniqueId },
    ): Promise<FordefiNativeSigner<TAddress> & FordefiSigner<TAddress>>;
    static async create<TAddress extends string = string>(
        config: FordefiSignerConfig,
    ): Promise<FordefiSigner<TAddress>>;
    static async create<TAddress extends string = string>(
        config: FordefiSignerConfig,
    ): Promise<FordefiSigner<TAddress>> {
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

        FordefiSigner.validatePollingConfig(
            config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS,
            config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
        );
        FordefiSigner.validateRequestDelayMs(config.requestDelayMs ?? 0);
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

        // Authoritative check: fetch the vault from Fordefi and verify that
        // `config.publicKey` actually belongs to `config.vaultId`. Without this
        // a valid-but-wrong address would pass configuration and later be
        // returned by resolveAddress(), creating a funds-routing risk.
        const verifiedAddress = await FordefiSigner.fetchAndVerifyVaultAddress({
            accessToken: config.accessToken,
            apiBaseUrl,
            expectedPublicKey: config.publicKey,
            vaultId: config.vaultId,
        });

        return new FordefiSigner<TAddress>(config, verifiedAddress as Address<TAddress>);
    }

    /**
     * Fetch the vault from Fordefi and assert the returned Solana address
     * matches `expectedPublicKey`.
     */
    private static async fetchAndVerifyVaultAddress({
        accessToken,
        apiBaseUrl,
        expectedPublicKey,
        vaultId,
    }: {
        accessToken: string;
        apiBaseUrl: string;
        expectedPublicKey: string;
        vaultId: string;
    }): Promise<Address> {
        const url = `${apiBaseUrl}/api/v1/vaults/${vaultId}`;
        const vault = await fetchSignerJson<FordefiVaultResponse>({
            init: {
                headers: { Authorization: `Bearer ${accessToken}` },
                method: 'GET',
            },
            providerName: 'Fordefi',
            timeoutMs: 10_000,
            url,
        });

        // Regular Fordefi Solana vaults expose `address` directly; black_box vaults
        // only provide `public_key_compressed` (base64-encoded Ed25519 key).
        let remoteAddress = vault.address;
        if (!remoteAddress && vault.public_key_compressed) {
            try {
                const keyBytes = new Uint8Array(Buffer.from(vault.public_key_compressed, 'base64'));
                remoteAddress = getBase58Decoder().decode(keyBytes);
            } catch (error) {
                return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                    cause: error,
                    message: 'Failed to derive Solana address from vault public_key_compressed',
                });
            }
        }
        if (!remoteAddress) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message:
                    'Fordefi vault response included neither `address` nor `public_key_compressed`; cannot verify publicKey ownership',
            });
        }

        if (remoteAddress !== expectedPublicKey) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Configured publicKey does not match Fordefi vault ${vaultId}: expected ${remoteAddress}`,
            });
        }

        try {
            assertIsAddress(remoteAddress);
        } catch (error) {
            return throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Fordefi vault returned an invalid Solana address',
            });
        }

        return remoteAddress;
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

    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const signatureBytes = await this.signMessage(message.content);
                await assertSignatureValid({
                    data: message.content,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        if (this.chain) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                address: this.address,
                message:
                    'Fordefi native Solana mode modifies and auto-broadcasts transactions; use signAndSendTransactions() or signAndSendTransactionMessageWithSigners()',
            });
        }

        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const { sigDict, verificationData } = await this.signBlackBoxTransaction(transaction.messageBytes);
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
            }),
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
    ): Promise<{ sigDict: SignatureDictionary; verificationData: Uint8Array }> {
        const bytes = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(Array.from(messageBytes));
        const base64Data = Buffer.from(bytes).toString('base64');

        const txId = await this.submitBlackBoxSignature(base64Data);
        const result = await this.pollForResult(txId, { pushable: false });
        const sigBase64 = this.extractSignatureData(result);
        const sigBytes = new Uint8Array(Buffer.from(sigBase64, 'base64'));
        if (sigBytes.length !== 64) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected 64-byte Ed25519 signature, got ${sigBytes.length}`,
            });
        }
        return {
            sigDict: createSignatureDictionary({ signature: sigBytes as SignatureBytes, signerAddress: this.address }),
            verificationData: bytes,
        };
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

        return await Promise.all(
            transactions.map(async (transaction, index) => {
                config?.abortSignal?.throwIfAborted();
                await this.delay(index);
                config?.abortSignal?.throwIfAborted();
                this.assertNativeAutoTransactionSupported(transaction);

                const base64Data = Buffer.from(transaction.messageBytes).toString('base64');
                const txId = await this.submitSolanaTransaction(base64Data);
                const result = await this.pollForResult(txId, { pushable: true });
                if (!result.raw_transaction) {
                    return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        message: 'Fordefi solana_transaction response missing raw_transaction',
                    });
                }

                const signedWireTx = result.raw_transaction as Base64EncodedWireTransaction;
                const sigDict = extractSignatureFromWireTransaction({
                    base64WireTransaction: signedWireTx,
                    signerAddress: this.address,
                });
                const signerSignature = sigDict[this.address];
                if (!signerSignature) {
                    return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        address: this.address,
                        message: 'Fordefi wire transaction did not contain the configured vault signature',
                    });
                }

                const { messageBytes, transactionSignature } = FordefiSigner.extractWireTransactionParts(signedWireTx);
                await assertSignatureValid({
                    data: messageBytes,
                    signature: signerSignature,
                    signerAddress: this.address,
                });
                config?.abortSignal?.throwIfAborted();
                return transactionSignature;
            }),
        );
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

    /**
     * POST a transaction request to Fordefi and return the transaction ID.
     * Shared by all signing modes (black_box, solana_transaction, solana_message).
     */
    private async submitTransaction(
        requestBody: FordefiBlackBoxSignatureRequest | FordefiSolanaMessageRequest | FordefiSolanaTransactionRequest,
    ): Promise<string> {
        const apiPath = '/api/v1/transactions';
        const createResponse = await this.request<FordefiCreateTransactionResponse>(
            'POST',
            apiPath,
            JSON.stringify(requestBody),
        );
        return createResponse.id;
    }

    /**
     * Submit a black_box_signature request for raw EdDSA signing.
     */
    private async submitBlackBoxSignature(base64Data: string): Promise<string> {
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
        return await this.submitTransaction(requestBody);
    }

    /**
     * Submit a native Solana serialized transaction message for signing + auto-push.
     */
    private async submitSolanaTransaction(base64Data: string): Promise<string> {
        const requestBody: FordefiSolanaTransactionRequest = {
            details: {
                chain: this.chain!,
                data: base64Data,
                ...(this.fee ? { fee: this.fee } : {}),
                push_mode: 'auto',
                type: 'solana_serialized_transaction_message',
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'solana_transaction',
            vault_id: this.vaultId,
        };
        return await this.submitTransaction(requestBody);
    }

    /**
     * Submit a native Solana personal message for signing.
     */
    private async submitSolanaMessage(base64Data: string): Promise<string> {
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
        return await this.submitTransaction(requestBody);
    }

    /**
     * Sign a Solana personal message via Fordefi MPC.
     * Submits the message, polls for completion, and returns the raw 64-byte Ed25519 signature.
     */
    private async signMessage(messageBytes: Uint8Array): Promise<SignatureBytes> {
        const base64Data = Buffer.from(messageBytes).toString('base64');

        const txId = this.chain
            ? await this.submitSolanaMessage(base64Data)
            : await this.submitBlackBoxSignature(base64Data);
        const result = await this.pollForResult(txId, { pushable: false });
        const sigBase64 = this.extractSignatureData(result);

        let sigBytes: Uint8Array;
        try {
            sigBytes = new Uint8Array(Buffer.from(sigBase64, 'base64'));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi signature base64',
            });
        }

        if (sigBytes.length !== 64) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected 64-byte Ed25519 signature, got ${sigBytes.length}`,
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
    ): Promise<FordefiTransactionStatusResponse> {
        const successStates = pushable ? PUSHABLE_SUCCESS_STATES : NON_PUSHABLE_SUCCESS_STATES;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const txData = await this.request<FordefiTransactionStatusResponse>('GET', `/api/v1/transactions/${txId}`);

            if (successStates.has(txData.state)) {
                return txData;
            }

            if (FAILURE_STATES.has(txData.state)) {
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Transaction ${txId} reached terminal state: ${txData.state}`,
                });
            }

            if (attempt + 1 < this.maxPollAttempts) {
                await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
            }
        }

        return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Polling timeout after ${this.maxPollAttempts} attempts`,
        });
    }

    /**
     * Extract the base64-encoded signature from a poll result.
     */
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

    /**
     * Make an authenticated request to the Fordefi API.
     */
    private async request<T>(
        method: 'GET' | 'POST',
        apiPath: string,
        body?: string,
        timeoutMs = this.requestTimeoutMs,
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

        return await fetchSignerJson<T>({
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

    private static validateRequestDelayMs(requestDelayMs: number): void {
        if (requestDelayMs < 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestDelayMs must not be negative',
            });
        }
        if (requestDelayMs > 3000) {
            console.warn('requestDelayMs is greater than 3000ms, this may result in blockhash expiration errors');
        }
    }

    private static validateRequestTimeoutMs(requestTimeoutMs: number): void {
        if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestTimeoutMs must be a positive finite number',
            });
        }
    }

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Extract the message bytes portion from a base64-encoded wire transaction.
     * Wire format: [compact-u16 sig_count][sig_count * 64 bytes][message bytes]
     */
    private static extractWireTransactionParts(base64WireTx: Base64EncodedWireTransaction): {
        messageBytes: Uint8Array;
        transactionSignature: SignatureBytes;
    } {
        const wireBytes = new Uint8Array(Buffer.from(base64WireTx, 'base64'));
        let signatureCount = 0;
        let signatureCountSize = 0;
        let shift = 0;
        let terminated = false;

        while (signatureCountSize < 3) {
            const byte = wireBytes[signatureCountSize];
            if (byte === undefined) {
                return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                    message: 'Fordefi wire transaction is missing its signature count',
                });
            }
            signatureCount |= (byte & 0x7f) << shift;
            signatureCountSize++;
            if ((byte & 0x80) === 0) {
                terminated = true;
                break;
            }
            shift += 7;
        }

        if (!terminated) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Fordefi wire transaction has an invalid signature count',
            });
        }

        if (signatureCount < 1) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Fordefi wire transaction has no signatures',
            });
        }

        const messageStart = signatureCountSize + signatureCount * 64;
        if (wireBytes.length <= messageStart) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Fordefi wire transaction is truncated',
            });
        }

        return {
            messageBytes: wireBytes.subarray(messageStart),
            transactionSignature: new Uint8Array(
                wireBytes.subarray(signatureCountSize, signatureCountSize + 64),
            ) as SignatureBytes,
        };
    }
}
