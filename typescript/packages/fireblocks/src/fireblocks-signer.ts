import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    signBatchStaggered,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

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
    private privateKeyPromise: Promise<CryptoKey> | null = null;
    private readonly apiKey: string;
    private readonly privateKeyPem: string;
    private readonly vaultAccountId: string;
    private readonly assetId: string;
    private readonly apiBaseUrl: string;
    private readonly pollIntervalMs: number;
    private readonly maxPollAttempts: number;
    private readonly requestDelayMs: number;
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

        if (config.useProgramCall === true) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message:
                    'useProgramCall (Fireblocks PROGRAM_CALL signing) is not supported: it broadcasts the transaction on-chain without producing a reusable signer-bound signature, which violates the SolanaSigner contract and risks duplicate spends. Use RAW signing (the default, omit useProgramCall) instead.',
            });
        }

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

    /**
     * Initialize the signer by fetching the public key from Fireblocks
     * @deprecated Use `createFireblocksSigner()` instead, which handles initialization automatically.
     */
    async init(): Promise<void> {
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

    /**
     * Fetch the public key from Fireblocks API
     */
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

    /**
     * Make an authenticated request to Fireblocks API
     */
    private async request<T>(method: string, uri: string, body?: unknown): Promise<T> {
        const bodyStr = body ? JSON.stringify(body) : '';
        const token = await createJwt(this.apiKey, await this.getPrivateKey(), uri, bodyStr);

        return await fetchSignerJson<T>({
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
     * Poll for transaction completion and extract a reusable signer-bound signature.
     */
    private async pollForSignature(transactionId: string): Promise<SignatureBytes> {
        const uri = `/v1/transactions/${encodeURIComponent(transactionId)}`;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const txResponse = await this.request<TransactionResponse>('GET', uri);

            const status = txResponse.status as FireblocksTransactionStatus;

            if (txResponse.status === 'COMPLETED') {
                // RAW signing returns the signature in signedMessages (hex encoded)
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
                    if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
                        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                            message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${sigBytes.length}`,
                        });
                    }
                    return sigBytes as SignatureBytes;
                }

                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: 'No signature found in response (no signedMessages)',
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

        return await signBatchStaggered(
            messages,
            async message => {
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
            },
            this.requestDelayMs,
        );
    }

    /**
     * Sign multiple transactions using Fireblocks
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await signBatchStaggered(
            transactions,
            async transaction => {
                const signatureBytes = await this.signRawBytes(new Uint8Array(transaction.messageBytes));
                await assertSignatureValid({
                    data: transaction.messageBytes,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            },
            this.requestDelayMs,
        );
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
