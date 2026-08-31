import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase58Encoder, getUtf8Encoder } from '@solana/codecs-strings';
import {
    abortableDelay,
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    idempotencyKeyFromMessage,
    normalizeMessageBytes,
    providerMayHaveAccepted,
    providerStatus,
    signBatchSequential,
    signBatchStaggered,
    SignerError,
    SignerErrorCode,
    SolanaMessageSigner,
    SolanaTransactionSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import {
    MessagePartialSignerConfig,
    SignableMessage,
    SignatureDictionary,
    TransactionPartialSignerConfig,
} from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import { createJwt, importFireblocksPrivateKey } from './jwt.js';
import type {
    CreateTransactionRequest,
    CreateTransactionResponse,
    FireblocksSignerConfig,
    TransactionResponse,
    VaultAddress,
    VaultAddressesResponse,
} from './types.js';
import { FireblocksTransactionStatus, isTerminalStatus } from './types.js';

/**
 * Create and initialize a Fireblocks-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`, `SIGNER_PARSING_ERROR`,
 * or `SIGNER_INVALID_PUBLIC_KEY` when signer initialization fails.
 */
export async function createFireblocksSigner<TAddress extends string = string>(
    config: FireblocksSignerConfig,
): Promise<SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress>> {
    return await FireblocksSigner.create(config);
}

let base16Encoder: ReturnType<typeof getBase16Encoder> | undefined;
let base16Decoder: ReturnType<typeof getBase16Decoder> | undefined;
let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
let utf8Encoder: ReturnType<typeof getUtf8Encoder> | undefined;

/** The version prefix sets the high bit of the first message byte, low bits hold the version. */
function isV1Message(messageBytes: Transaction['messageBytes']): boolean {
    const prefix = messageBytes[0] ?? 0;
    return (prefix & 0x80) !== 0 && (prefix & 0x7f) === 1;
}

const DEFAULT_API_BASE_URL = 'https://api.fireblocks.io';
const DEFAULT_ASSET_ID = 'SOL';
const DEFAULT_POLL_INTERVAL_MS = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS = 60;

/**
 * Fireblocks-based signer for Solana transactions
 *
 * Uses Fireblocks Raw Message Signing to sign Solana transactions and messages,
 * or sign-only PROGRAM_CALL for transactions when `useProgramCall` is set.
 * Requires a Fireblocks account with a Solana vault account configured.
 *
 * @example
 * ```typescript
 * const signer = await createFireblocksSigner({
 *     apiKey: 'your-api-key',
 *     privateKeyPem: '-----BEGIN PRIVATE KEY-----\n...',
 *     vaultAccountId: '0',
 * });
 * ```
 */
class FireblocksSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    private _address: Address<TAddress> | null = null;
    private privateKeyPromise: Promise<CryptoKey> | null = null;
    private readonly apiKey: string;
    private readonly privateKeyPem: string;
    private readonly vaultAccountId: string;
    private readonly assetId: string;
    private readonly apiBaseUrl: string;
    private readonly pollIntervalMs: number;
    private readonly maxPollAttempts: number;
    private readonly requestDelayMs: number;
    private readonly useProgramCall: boolean;
    private initialized = false;

    /**
     * Fetches the public key from Fireblocks API during initialization.
     */
    static async create<TAddress extends string = string>(
        config: FireblocksSignerConfig,
    ): Promise<FireblocksSigner<TAddress>> {
        const signer = new FireblocksSigner<TAddress>(config);
        await signer.init();
        return signer;
    }

    private constructor(config: FireblocksSignerConfig) {
        if (!config.apiKey) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required apiKey field',
            });
        }

        if (!config.privateKeyPem) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required privateKeyPem field',
            });
        }

        if (!config.vaultAccountId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required vaultAccountId field',
            });
        }

        this.useProgramCall = config.useProgramCall === true;
        this.apiKey = config.apiKey;
        this.privateKeyPem = config.privateKeyPem;
        this.vaultAccountId = config.vaultAccountId;
        this.assetId = config.assetId ?? DEFAULT_ASSET_ID;
        const apiBaseUrl = config.apiBaseUrl ?? DEFAULT_API_BASE_URL;
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

        this.apiBaseUrl = apiBaseUrl;
        this.pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        this.maxPollAttempts = config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS;
        this.requestDelayMs = config.requestDelayMs ?? 0;

        validateRequestDelayMs(this.requestDelayMs);
    }

    /**
     * Get the public key address of this signer
     * @throws {SignerError} If the signer has not been initialized
     */
    get address(): Address<TAddress> {
        if (!this._address) {
            throwSignerError(SignerErrorCode.SIGNER_NOT_INITIALIZED, {
                message: 'Signer not initialized. Call init() first.',
            });
        }
        return this._address;
    }

    private async init(): Promise<void> {
        if (this.initialized) {
            return;
        }

        await this.getPrivateKey();
        const pubkey = await this.fetchPublicKey();
        this._address = pubkey as Address<TAddress>;
        this.initialized = true;
    }

    /**
     * Get the imported RSA signing key, importing it from the configured PEM
     * on first use and caching it for all subsequent JWT mints. The pending
     * promise is cached (not the resolved key) so concurrent callers share a
     * single import.
     */
    private getPrivateKey(): Promise<CryptoKey> {
        this.privateKeyPromise ??= importFireblocksPrivateKey(this.privateKeyPem);
        return this.privateKeyPromise;
    }

    private async fetchPublicKey(): Promise<Address> {
        const uri = `/v1/vault/accounts/${encodeURIComponent(this.vaultAccountId)}/${encodeURIComponent(this.assetId)}/addresses_paginated`;
        const addressesResponse = await this.request<VaultAddressesResponse>('GET', uri);

        const address = this.selectVaultAddress(addressesResponse.addresses ?? []);

        try {
            assertIsAddress(address);
            return address;
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Invalid address from Fireblocks',
            });
        }
    }

    /**
     * Pick the address for the configured asset, failing on an empty or ambiguous
     * response: a mistyped vault account or asset id must not yield a working
     * signer bound to an unintended fee payer. Entries without an `assetId` are
     * kept, since the endpoint is already scoped by asset.
     */
    private selectVaultAddress(addresses: readonly VaultAddress[]): string {
        const unique = [
            ...new Set(
                addresses
                    .filter(entry => entry.address && (!entry.assetId || entry.assetId === this.assetId))
                    .map(entry => entry.address),
            ),
        ];
        if (unique.length === 1) {
            return unique[0]!;
        }
        throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
            message:
                unique.length === 0
                    ? `Fireblocks returned no address for vault account ${this.vaultAccountId} asset ${this.assetId}`
                    : `Fireblocks returned ${unique.length} addresses for vault account ${this.vaultAccountId} asset ${this.assetId}; cannot choose a signing identity`,
        });
    }

    private async request<T>(method: string, uri: string, body?: unknown, abortSignal?: AbortSignal): Promise<T> {
        const bodyStr = body ? JSON.stringify(body) : '';
        const token = await createJwt(this.apiKey, await this.getPrivateKey(), uri, bodyStr);

        return await fetchSignerJson<T>({
            abortSignal,
            init: {
                body: body ? bodyStr : undefined,
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'X-API-Key': this.apiKey,
                },
                method,
            },
            providerName: 'Fireblocks',
            url: `${this.apiBaseUrl}${uri}`,
        });
    }

    private async signRawBytes(messageBytes: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        base16Decoder ||= getBase16Decoder();
        const hexContent = base16Decoder.decode(messageBytes);

        const request: CreateTransactionRequest = {
            assetId: this.assetId,
            extraParameters: {
                rawMessageData: {
                    messages: [{ content: hexContent }],
                },
            },
            operation: 'RAW',
            source: {
                id: this.vaultAccountId,
                type: 'VAULT_ACCOUNT',
            },
        };

        const createResponse = await this.request<CreateTransactionResponse>(
            'POST',
            '/v1/transactions',
            request,
            abortSignal,
        );
        return await this.pollForSignature(createResponse.id, 'RAW', abortSignal);
    }

    /**
     * Sign a transaction with the PROGRAM_CALL operation in sign-only mode.
     *
     * Fireblocks returns the signature either in `signedMessages` or as the
     * `txHash` of the signed transaction, so both carriers are accepted; the
     * caller verifies the bytes against the vault address before use.
     */
    private async signProgramCall(
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
        abortSignal?: AbortSignal,
    ): Promise<SignatureBytes> {
        if (isV1Message(transaction.messageBytes)) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message:
                    'Fireblocks PROGRAM_CALL accepts legacy and v0 messages only; a v1 message cannot be signed in this mode',
            });
        }

        const externalTxId = await this.externalTxId(transaction.messageBytes);
        const request: CreateTransactionRequest = {
            assetId: this.assetId,
            externalTxId,
            extraParameters: {
                programCallData: getBase64EncodedWireTransaction(transaction),
                signOnly: true,
                useDurableNonce: false,
            },
            operation: 'PROGRAM_CALL',
            source: {
                id: this.vaultAccountId,
                type: 'VAULT_ACCOUNT',
            },
        };

        const transactionId = await this.createProgramCallTransaction(request, externalTxId, abortSignal);
        return await this.pollForSignature(transactionId, 'PROGRAM_CALL', abortSignal);
    }

    /** Creates a PROGRAM_CALL signing request. */
    private async createProgramCallTransaction(
        request: CreateTransactionRequest,
        externalTxId: string,
        abortSignal?: AbortSignal,
    ): Promise<string> {
        let createResponse: CreateTransactionResponse;
        try {
            createResponse = await this.request<CreateTransactionResponse>(
                'POST',
                '/v1/transactions',
                request,
                abortSignal,
            );
        } catch (error) {
            if (!providerMayHaveAccepted(error)) {
                throw error;
            }
            const status = providerStatus(error);
            const providerTransactionId =
                error instanceof SignerError ? error.context?.providerTransactionId : undefined;
            return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                cause: error,
                idempotencyKey: externalTxId,
                message:
                    typeof providerTransactionId === 'string'
                        ? `Fireblocks may have accepted the PROGRAM_CALL, but the outcome could not be confirmed (provider transaction id: ${providerTransactionId})`
                        : 'Fireblocks may have accepted the PROGRAM_CALL, but the outcome could not be confirmed and no transaction id was returned',
                ...(status === undefined ? {} : { status }),
                ...(typeof providerTransactionId === 'string' ? { providerTransactionId } : {}),
            });
        }
        if (typeof createResponse.id !== 'string' || createResponse.id.length === 0) {
            return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                idempotencyKey: externalTxId,
                message:
                    'Fireblocks accepted the PROGRAM_CALL but returned no transaction id, so the outcome cannot be confirmed',
            });
        }
        return createResponse.id;
    }

    private async externalTxId(messageBytes: ArrayLike<number>): Promise<string> {
        utf8Encoder ||= getUtf8Encoder();
        const namespace = utf8Encoder.encode(`fireblocks:solana:program_call:${this.assetId}:${this.vaultAccountId}:`);
        const bytes = normalizeMessageBytes(messageBytes);
        const namespaced = new Uint8Array(namespace.length + bytes.length);
        namespaced.set(namespace);
        namespaced.set(bytes, namespace.length);
        return await idempotencyKeyFromMessage(namespaced);
    }

    /**
     * Poll for transaction completion and extract a reusable signer-bound signature.
     */
    private async pollForSignature(
        transactionId: string,
        operation: 'PROGRAM_CALL' | 'RAW',
        abortSignal?: AbortSignal,
    ): Promise<SignatureBytes> {
        const uri = `/v1/transactions/${encodeURIComponent(transactionId)}`;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            let txResponse: TransactionResponse;
            try {
                txResponse = await this.request<TransactionResponse>('GET', uri, undefined, abortSignal);
            } catch (error) {
                if (operation !== 'PROGRAM_CALL' || abortSignal?.aborted === true) {
                    throw error;
                }
                return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                    cause: error,
                    message: 'Fireblocks PROGRAM_CALL outcome could not be resolved',
                    providerTransactionId: transactionId,
                });
            }

            const status = txResponse.status as FireblocksTransactionStatus;

            if (operation === 'PROGRAM_CALL') {
                if (status === 'SIGNED') {
                    return this.extractSignature(txResponse, true);
                }

                if (status === 'BROADCASTING' || status === 'CONFIRMING' || status === 'COMPLETED') {
                    return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        message: `Fireblocks broadcast the PROGRAM_CALL despite signOnly (status ${status}); the transaction may already be executing`,
                        providerTransactionId: transactionId,
                    });
                }
            } else if (status === 'COMPLETED') {
                return this.extractSignature(txResponse, false);
            }

            if (isTerminalStatus(status)) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Transaction failed with status: ${txResponse.status}`,
                });
            }

            await abortableDelay(this.pollIntervalMs, abortSignal);
        }

        if (operation === 'PROGRAM_CALL') {
            return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                message: `Fireblocks PROGRAM_CALL did not resolve within ${this.maxPollAttempts} attempts; the transaction may already be executing`,
                providerTransactionId: transactionId,
            });
        }
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: `Transaction did not complete within ${this.maxPollAttempts} attempts`,
        });
    }

    private extractSignature(txResponse: TransactionResponse, allowTxHashCarrier: boolean): SignatureBytes {
        const fullSig = txResponse.signedMessages?.[0]?.signature?.fullSig;
        if (fullSig) {
            const cleanHex = fullSig.startsWith('0x') || fullSig.startsWith('0X') ? fullSig.slice(2) : fullSig;
            if (cleanHex.length % 2 !== 0) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Invalid hex signature: odd length (${cleanHex.length} chars)`,
                });
            }
            base16Encoder ||= getBase16Encoder();
            return this.assertSignatureLength(new Uint8Array(base16Encoder.encode(cleanHex.toLowerCase())));
        }

        if (allowTxHashCarrier && txResponse.txHash) {
            base58Encoder ||= getBase58Encoder();
            let sigBytes: Uint8Array;
            try {
                sigBytes = new Uint8Array(base58Encoder.encode(txResponse.txHash));
            } catch (error) {
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    cause: error,
                    message: 'Failed to decode base58 signature',
                });
            }
            return this.assertSignatureLength(sigBytes);
        }

        return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: 'No signature found in response (no signedMessages)',
        });
    }

    private assertSignatureLength(sigBytes: Uint8Array): SignatureBytes {
        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${sigBytes.length}`,
            });
        }
        return sigBytes as SignatureBytes;
    }

    /**
     * Sign multiple messages using Fireblocks
     */
    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes = normalizeMessageBytes(message.content);
                const signatureBytes = await this.signRawBytes(messageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: messageBytes,
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
     * Sign multiple transactions using Fireblocks
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        const signOne = async (transaction: (typeof transactions)[number]): Promise<SignatureDictionary> => {
            const signatureBytes = this.useProgramCall
                ? await this.signProgramCall(transaction, config?.abortSignal)
                : await this.signRawBytes(normalizeMessageBytes(transaction.messageBytes), config?.abortSignal);
            await assertSignatureValid({
                data: transaction.messageBytes,
                signature: signatureBytes,
                signerAddress: this.address,
            });
            return createSignatureDictionary({
                signature: signatureBytes,
                signerAddress: this.address,
            });
        };

        if (this.useProgramCall) {
            return await signBatchSequential(
                transactions,
                signOne,
                this.requestDelayMs,
                'completedSignatures',
                config?.abortSignal,
            );
        }
        return await signBatchStaggered(transactions, signOne, this.requestDelayMs, config?.abortSignal);
    }

    /**
     * Check if Fireblocks API is available
     */
    async isAvailable(): Promise<boolean> {
        try {
            await this.request<unknown>('GET', `/v1/vault/accounts/${encodeURIComponent(this.vaultAccountId)}`);
            return true;
        } catch {
            return false;
        }
    }

    private ensureInitialized(): void {
        if (!this.initialized) {
            throwSignerError(SignerErrorCode.SIGNER_NOT_INITIALIZED, {
                message: 'Signer not initialized. Call init() first.',
            });
        }
    }
}
