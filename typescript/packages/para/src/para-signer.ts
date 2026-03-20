import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    batchSign,
    createBatchDelay,
    fetchWithSignerErrors,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateHttpsUrl,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
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
): Promise<SolanaSigner<TAddress>> {
    return await ParaSigner.create(config);
}

const DEFAULT_BASE_URL = 'https://api.getpara.com';
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
 *
 * @deprecated Prefer `createParaSigner()`. Class export will be removed in a future version.
 */
export class ParaSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiKey: string;
    private readonly apiBaseUrl: string;
    private readonly delay: (index: number) => Promise<void>;
    private readonly walletId: string;

    private constructor(
        config: ParaSignerConfig & { delay: (index: number) => Promise<void>; validatedBaseUrl: string },
        address: Address<TAddress>,
    ) {
        this.apiKey = config.apiKey;
        this.apiBaseUrl = config.validatedBaseUrl;
        this.walletId = config.walletId;
        this.address = address;
        this.delay = config.delay;
    }

    /**
     * Create a ParaSigner by fetching the wallet's public key from Para's API
     * @deprecated Use `createParaSigner()` instead.
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

        const apiBaseUrl = (config.apiBaseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
        validateHttpsUrl(apiBaseUrl, 'apiBaseUrl');
        const delay = createBatchDelay(config.requestDelayMs ?? 0);
        const url = `${apiBaseUrl}/v1/wallets/${config.walletId}`;

        const wallet = await fetchWithSignerErrors<ParaWalletResponse>(
            url,
            {
                headers: {
                    'X-API-Key': config.apiKey,
                },
                method: 'GET',
            },
            'Para',
        );

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

        return new ParaSigner<TAddress>(
            { ...config, delay, validatedBaseUrl: apiBaseUrl },
            wallet.address as Address<TAddress>,
        );
    }

    /**
     * Check if the Para wallet is available and ready for signing
     */
    async isAvailable(): Promise<boolean> {
        const url = `${this.apiBaseUrl}/v1/wallets/${this.walletId}`;

        try {
            const response = await fetch(url, {
                headers: { 'X-API-Key': this.apiKey },
                method: 'GET',
                signal: AbortSignal.timeout(5_000),
            });

            if (!response.ok) return false;

            const wallet = (await response.json()) as ParaWalletResponse;
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
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: messages,
            signFn: async m => {
                const sig = await this.signBytes(m.content);
                await assertSignatureValid({ data: m.content, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    /**
     * Sign multiple transactions using Para
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: transactions,
            signFn: async tx => {
                const sig = await this.signBytes(tx.messageBytes);
                await assertSignatureValid({ data: tx.messageBytes, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    /**
     * Sign raw bytes via Para's /sign-raw endpoint
     */
    private async signBytes(data: ArrayLike<number>): Promise<SignatureBytes> {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(Array.from(data));
        const hexData = getBase16Decoder().decode(bytes);

        const url = `${this.apiBaseUrl}/v1/wallets/${this.walletId}/sign-raw`;
        const request: ParaSignRawRequest = {
            data: hexData,
            encoding: 'hex',
        };

        const signResponse = await fetchWithSignerErrors<ParaSignRawResponse>(
            url,
            {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': this.apiKey,
                },
                method: 'POST',
            },
            'Para',
        );

        if (!signResponse.signature) {
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Para response',
            });
        }

        return this.decodeHexSignature(signResponse.signature);
    }

    /**
     * Decode a hex-encoded Ed25519 signature to SignatureBytes
     */
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
