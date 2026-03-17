import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase58Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import { createJwt } from './jwt.js';
import type {
    CreateTransactionRequest,
    CreateTransactionResponse,
    FireblocksSignerConfig,
    TransactionResponse,
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
): Promise<SolanaSigner<TAddress>> {
    return await FireblocksSigner.create(config);
}

let base16Encoder: ReturnType<typeof getBase16Encoder> | undefined;
let base16Decoder: ReturnType<typeof getBase16Decoder> | undefined;

const DEFAULT_API_BASE_URL = 'https://api.fireblocks.io';
const DEFAULT_ASSET_ID = 'SOL';
const DEFAULT_POLL_INTERVAL_MS = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS = 60;

/**
 * Fireblocks-based signer for Solana transactions
 *
 * Uses Fireblocks Raw Message Signing to sign Solana transactions and messages.
 * Requires a Fireblocks account with a Solana vault account configured.
 *
 * @example
 * ```typescript
 * const signer = await FireblocksSigner.create({
 *     apiKey: 'your-api-key',
 *     privateKeyPem: '-----BEGIN PRIVATE KEY-----\n...',
 *     vaultAccountId: '0',
 * });
 * ```
 *
 * @deprecated Prefer `createFireblocksSigner()`. Class export will be removed in a future version.
 */
export class FireblocksSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    private _address: Address<TAddress> | null = null;
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
     * @deprecated Use `createFireblocksSigner()` instead.
     */
    static async create<TAddress extends string = string>(
        config: FireblocksSignerConfig,
    ): Promise<FireblocksSigner<TAddress>> {
        const signer = new FireblocksSigner<TAddress>(config);
        await signer.init();
        return signer;
    }

    /**
     * @deprecated Use `createFireblocksSigner()` instead. Direct construction will be removed in a future version.
     */
    constructor(config: FireblocksSignerConfig) {
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

        this.apiKey = config.apiKey;
        this.privateKeyPem = config.privateKeyPem;
        this.vaultAccountId = config.vaultAccountId;
        this.assetId = config.assetId ?? DEFAULT_ASSET_ID;
        const apiBaseUrl = config.apiBaseUrl ?? DEFAULT_API_BASE_URL;
        validateHttpsApiBaseUrl(apiBaseUrl);

        this.apiBaseUrl = apiBaseUrl;
        this.pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        this.maxPollAttempts = config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS;
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.useProgramCall = config.useProgramCall ?? false;

        this.validateRequestDelayMs(this.requestDelayMs);
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

    /**
     * Initialize the signer by fetching the public key from Fireblocks
     * @deprecated Use `createFireblocksSigner()` instead, which handles initialization automatically.
     */
    async init(): Promise<void> {
        if (this.initialized) {
            return;
        }

        const pubkey = await this.fetchPublicKey();
        this._address = pubkey as Address<TAddress>;
        this.initialized = true;
    }

    /**
     * Validate request delay ms
     */
    private validateRequestDelayMs(requestDelayMs: number): void {
        if (requestDelayMs < 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestDelayMs must not be negative',
            });
        }
        if (requestDelayMs > 3000) {
            console.warn(
                'requestDelayMs is greater than 3000ms, this may result in blockhash expiration errors for signing messages/transactions',
            );
        }
    }

    /**
     * Add delay between concurrent requests
     */
    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Fetch the public key from Fireblocks API
     */
    private async fetchPublicKey(): Promise<Address> {
        const uri = `/v1/vault/accounts/${this.vaultAccountId}/${this.assetId}/addresses_paginated`;
        const token = await createJwt(this.apiKey, this.privateKeyPem, uri, '');

        const url = `${this.apiBaseUrl}${uri}`;
        let response: Response;
        try {
            response = await fetch(url, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'X-API-Key': this.apiKey,
                },
                method: 'GET',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Fireblocks network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Fireblocks API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let addressesResponse: VaultAddressesResponse;
        try {
            addressesResponse = (await response.json()) as VaultAddressesResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Fireblocks response',
            });
        }

        const firstAddress = addressesResponse.addresses?.[0]?.address;
        if (!firstAddress) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                message: 'No addresses found in Fireblocks vault',
            });
        }

        try {
            assertIsAddress(firstAddress);
            return firstAddress as Address;
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Invalid address from Fireblocks',
            });
        }
    }

    /**
     * Make an authenticated request to Fireblocks API
     */
    private async request<T>(method: string, uri: string, body?: unknown): Promise<T> {
        const bodyStr = body ? JSON.stringify(body) : '';
        const token = await createJwt(this.apiKey, this.privateKeyPem, uri, bodyStr);

        const url = `${this.apiBaseUrl}${uri}`;
        let response: Response;
        try {
            response = await fetch(url, {
                body: body ? bodyStr : undefined,
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'X-API-Key': this.apiKey,
                },
                method,
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Fireblocks network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Fireblocks API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        try {
            return (await response.json()) as T;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Fireblocks response',
            });
        }
    }

    /**
     * Sign raw bytes using Fireblocks RAW operation
     */
    private async signRawBytes(messageBytes: Uint8Array): Promise<SignatureBytes> {
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

        const createResponse = await this.request<CreateTransactionResponse>('POST', '/v1/transactions', request);
        return await this.pollForSignature(createResponse.id);
    }

    /**
     * Sign a transaction using Fireblocks PROGRAM_CALL operation
     * This broadcasts the transaction to Solana through Fireblocks
     */
    private async signWithProgramCall(
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<SignatureBytes> {
        // Use the same serialization as Privy - proper wire format with all signatures
        const base64WireTransaction = getBase64EncodedWireTransaction(transaction);

        const request: CreateTransactionRequest = {
            assetId: this.assetId,
            extraParameters: {
                programCallData: base64WireTransaction,
            },
            operation: 'PROGRAM_CALL',
            source: {
                id: this.vaultAccountId,
                type: 'VAULT_ACCOUNT',
            },
        };

        const createResponse = await this.request<CreateTransactionResponse>('POST', '/v1/transactions', request);
        return await this.pollForSignature(createResponse.id);
    }

    /**
     * Poll for transaction completion and extract signature
     */
    private async pollForSignature(transactionId: string): Promise<SignatureBytes> {
        const uri = `/v1/transactions/${transactionId}`;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const txResponse = await this.request<TransactionResponse>('GET', uri);

            const status = txResponse.status as FireblocksTransactionStatus;

            if (txResponse.status === 'COMPLETED') {
                // Try signedMessages first (RAW signing - hex encoded)
                const fullSig = txResponse.signedMessages?.[0]?.signature?.fullSig;
                if (fullSig) {
                    const cleanHex = fullSig.startsWith('0x') || fullSig.startsWith('0X') ? fullSig.slice(2) : fullSig;
                    if (cleanHex.length % 2 !== 0) {
                        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                            message: `Invalid hex signature: odd length (${cleanHex.length} chars)`,
                        });
                    }
                    base16Encoder ||= getBase16Encoder();
                    const sigBytes = new Uint8Array(base16Encoder.encode(cleanHex.toLowerCase()));
                    if (sigBytes.length !== 64) {
                        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                            message: `Invalid signature length: expected 64 bytes, got ${sigBytes.length}`,
                        });
                    }
                    return sigBytes as SignatureBytes;
                }

                // Try txHash (PROGRAM_CALL - base58 encoded signature)
                if (txResponse.txHash) {
                    const sigBytes = getBase58Encoder().encode(txResponse.txHash);
                    if (sigBytes.length !== 64) {
                        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                            message: `Invalid txHash length: expected 64 bytes, got ${sigBytes.length}`,
                        });
                    }
                    return sigBytes as SignatureBytes;
                }

                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: 'No signature found in response (no signedMessages or txHash)',
                });
            }

            // Check for terminal failure statuses
            if (isTerminalStatus(status)) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Transaction failed with status: ${txResponse.status}`,
                });
            }

            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
        }

        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: `Transaction did not complete within ${this.maxPollAttempts} attempts`,
        });
    }

    /**
     * Sign multiple messages using Fireblocks
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signRawBytes(messageBytes);
                await assertSignatureValid({
                    data: messageBytes,
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

    /**
     * Sign multiple transactions using Fireblocks
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const signatureBytes = this.useProgramCall
                    ? await this.signWithProgramCall(transaction)
                    : await this.signRawBytes(new Uint8Array(transaction.messageBytes));
                // Skip verification for PROGRAM_CALL: it broadcasts to Solana and returns
                // a txHash (on-chain confirmation), not a signature over the message bytes.
                if (!this.useProgramCall) {
                    await assertSignatureValid({
                        data: transaction.messageBytes,
                        signature: signatureBytes,
                        signerAddress: this.address,
                    });
                }
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Check if Fireblocks API is available
     */
    async isAvailable(): Promise<boolean> {
        try {
            const uri = `/v1/vault/accounts/${this.vaultAccountId}`;
            const token = await createJwt(this.apiKey, this.privateKeyPem, uri, '');

            const url = `${this.apiBaseUrl}${uri}`;
            const response = await fetch(url, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'X-API-Key': this.apiKey,
                },
                method: 'GET',
            });

            return response.ok;
        } catch {
            return false;
        }
    }

    /**
     * Ensure the signer has been initialized
     */
    private ensureInitialized(): void {
        if (!this.initialized) {
            throwSignerError(SignerErrorCode.SIGNER_NOT_INITIALIZED, {
                message: 'Signer not initialized. Call init() first.',
            });
        }
    }
}

function validateHttpsApiBaseUrl(apiBaseUrl: string): void {
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(apiBaseUrl);
    } catch {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'apiBaseUrl is not a valid URL',
        });
    }

    if (parsedUrl.protocol !== 'https:') {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'apiBaseUrl must use HTTPS',
        });
    }
}
