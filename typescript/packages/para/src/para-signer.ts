import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    fetchSignerJson,
    normalizeBaseUrl,
    signBatchStaggered,
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
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

import type { ParaSignRawRequest, ParaSignRawResponse, ParaWalletResponse } from './types.js';

/**
 * Create and initialize a Para-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`, or `SIGNER_PARSING_ERROR`
 * when initialization fails.
 */
export async function createParaSigner<TAddress extends string = string>(
    config: ParaSignerConfig,
): Promise<SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress>> {
    return await ParaSigner.create(config);
}

const DEFAULT_BASE_URL = 'https://api.getpara.com';
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const AVAILABILITY_TIMEOUT_MS = 5_000;

/**
 * Configuration for creating a ParaSigner
 */
export interface ParaSignerConfig {
    /** Para API base URL (default: https://api.getpara.com) */
    apiBaseUrl?: string;
    /** Para API key (server-side only) */
    apiKey: string;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
    /** Para wallet UUID */
    walletId: string;
}

/**
 * Para MPC signer using Para's REST API
 *
 * Uses the /v1/wallets/:walletId/sign-raw endpoint for Ed25519 signing.
 * Raw bytes are signed directly with no hashing or transformation.
 */
class ParaSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;
    private readonly apiKey: string;
    private readonly apiBaseUrl: string;
    private readonly requestDelayMs: number;
    private readonly walletId: string;

    private constructor(config: ParaSignerConfig & { apiBaseUrl: string }, address: Address<TAddress>) {
        this.apiKey = config.apiKey;
        this.apiBaseUrl = config.apiBaseUrl;
        this.walletId = config.walletId;
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.address = address;
        validateRequestDelayMs(this.requestDelayMs);
    }

    /**
     * Create a ParaSigner by fetching the wallet's public key from Para's API
     */
    static async create<TAddress extends string = string>(config: ParaSignerConfig): Promise<ParaSigner<TAddress>> {
        if (!config.apiKey || !config.walletId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required configuration fields (apiKey or walletId)',
            });
        }

        if (!config.apiKey.startsWith('sk_')) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'apiKey must be a Para secret key (starts with sk_)',
            });
        }

        if (!UUID_REGEX.test(config.walletId)) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'walletId must be a valid UUID',
            });
        }

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_BASE_URL);
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');
        const url = `${apiBaseUrl}/v1/wallets/${config.walletId}`;

        const wallet = await fetchSignerJson<ParaWalletResponse>({
            init: {
                headers: {
                    'X-API-Key': config.apiKey,
                },
                method: 'GET',
            },
            providerName: 'Para',
            url,
        });

        if (wallet.type?.toUpperCase() !== 'SOLANA') {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Expected SOLANA wallet but got ${wallet.type}`,
                walletId: config.walletId,
            });
        }

        if (!wallet.address) {
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Wallet does not have an address (may still be creating)',
                walletId: config.walletId,
            });
        }

        try {
            assertIsAddress(wallet.address);
        } catch (error) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana public key format',
            });
        }

        return new ParaSigner<TAddress>({ ...config, apiBaseUrl }, wallet.address as Address<TAddress>);
    }

    /**
     * Check if the Para wallet is available and ready for signing
     */
    async isAvailable(): Promise<boolean> {
        const url = `${this.apiBaseUrl}/v1/wallets/${this.walletId}`;

        try {
            const wallet = await fetchSignerJson<ParaWalletResponse>({
                init: {
                    headers: { 'X-API-Key': this.apiKey },
                    method: 'GET',
                },
                providerName: 'Para',
                timeoutMs: AVAILABILITY_TIMEOUT_MS,
                url,
            });

            const status = wallet.status?.toUpperCase();
            const isSolana = wallet.type?.toUpperCase() === 'SOLANA';
            return isSolana && (status === 'ACTIVE' || status === 'READY');
        } catch {
            return false;
        }
    }

    /**
     * Sign multiple messages using Para
     */
    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const signatureBytes = await this.signBytes(message.content, config?.abortSignal);
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
     * Sign multiple transactions using Para
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const signatureBytes = await this.signBytes(transaction.messageBytes, config?.abortSignal);
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
            config?.abortSignal,
        );
    }

    private async signBytes(data: ArrayLike<number>, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(Array.from(data));
        const hexData = getBase16Decoder().decode(bytes);

        const url = `${this.apiBaseUrl}/v1/wallets/${this.walletId}/sign-raw`;
        const request: ParaSignRawRequest = {
            data: hexData,
            encoding: 'hex',
        };

        const signResponse = await fetchSignerJson<ParaSignRawResponse>({
            abortSignal,
            init: {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': this.apiKey,
                },
                method: 'POST',
            },
            providerName: 'Para',
            url,
        });

        if (!signResponse.signature) {
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Para response',
            });
        }

        return this.decodeHexSignature(signResponse.signature);
    }

    private decodeHexSignature(hexSignature: string): SignatureBytes {
        const cleaned = hexSignature.startsWith('0x') ? hexSignature.slice(2) : hexSignature;

        if (!cleaned || cleaned.length !== 128) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: `Invalid Ed25519 signature length: expected 128 hex chars, got ${cleaned.length}`,
            });
        }

        if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Invalid hex characters in Ed25519 signature',
            });
        }

        return getBase16Encoder().encode(cleaned) as SignatureBytes;
    }
}
