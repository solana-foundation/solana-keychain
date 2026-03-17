import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder } from '@solana/codecs-strings';
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
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

import type { ParaErrorResponse, ParaSignRawRequest, ParaSignRawResponse, ParaWalletResponse } from './types.js';

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
    private readonly requestDelayMs: number;
    private readonly walletId: string;

    private constructor(config: ParaSignerConfig, address: Address<TAddress>) {
        this.apiKey = config.apiKey;
        this.apiBaseUrl = (config.apiBaseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
        this.walletId = config.walletId;
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.address = address;
        this.validateRequestDelayMs(this.requestDelayMs);
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

        let parsedUrl: URL;
        try {
            parsedUrl = new URL(apiBaseUrl);
        } catch {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'apiBaseUrl is not a valid URL',
            });
        }
        if (parsedUrl.protocol !== 'https:') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'apiBaseUrl must use HTTPS',
            });
        }
        const url = `${apiBaseUrl}/v1/wallets/${config.walletId}`;

        let response: Response;
        try {
            response = await fetch(url, {
                headers: {
                    'X-API-Key': config.apiKey,
                },
                method: 'GET',
            });
        } catch (error) {
            return throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Para network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorMessage = await ParaSigner.extractErrorMessage(response, 'Failed to fetch wallet');
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: errorMessage,
                status: response.status,
            });
        }

        let wallet: ParaWalletResponse;
        try {
            wallet = (await response.json()) as ParaWalletResponse;
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Para wallet response',
            });
        }

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

        return new ParaSigner<TAddress>(config, wallet.address as Address<TAddress>);
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
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const signatureBytes = await this.signBytes(message.content);
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

    /**
     * Sign multiple transactions using Para
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const signatureBytes = await this.signBytes(transaction.messageBytes);
                await assertSignatureValid({
                    data: transaction.messageBytes,
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

        let response: Response;
        try {
            response = await fetch(url, {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': this.apiKey,
                },
                method: 'POST',
            });
        } catch (error) {
            return throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Para network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorMessage = await ParaSigner.extractErrorMessage(response, 'Para signing failed');
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: errorMessage,
                status: response.status,
            });
        }

        let signResponse: ParaSignRawResponse;
        try {
            signResponse = (await response.json()) as ParaSignRawResponse;
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Para signing response',
            });
        }

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

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Extract error message from a Para API error response
     */
    private static async extractErrorMessage(response: Response, fallback: string): Promise<string> {
        let errorMessage = `${fallback}: ${response.status}`;
        try {
            const errorData = (await response.json()) as ParaErrorResponse;
            if (errorData.message) {
                errorMessage = `${fallback}: ${sanitizeRemoteErrorResponse(errorData.message)}`;
            }
        } catch {
            // Ignore JSON parsing errors for error response
        }
        return errorMessage;
    }
}
