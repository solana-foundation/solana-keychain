import { Address, assertIsAddress } from '@solana/addresses';
import { getBase64Decoder, getBase64Encoder, getUtf8Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    extractSignatureFromWireTransaction,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    Base64EncodedWireTransaction,
    getBase64EncodedWireTransaction,
    Transaction,
    TransactionMessageBytesBase64,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type { PrivyAuthorizationConfig } from './authorization.js';
import { getDefaultPrivyAuthorizationRequestExpiryMs, preparePrivyAuthorizationHeaders } from './authorization.js';
import {
    SignatureBytesBase64,
    SignMessageRequest,
    SignMessageResponse,
    SignTransactionRequest,
    SignTransactionResponse,
    WalletResponse,
} from './types.js';

/**
 * Create and initialize a Privy-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`, or `SIGNER_PARSING_ERROR`
 * when the Privy initialization request fails.
 */
export async function createPrivySigner<TAddress extends string = string>(
    config: PrivySignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await PrivySigner.create(config);
}

const DEFAULT_API_BASE_URL = 'https://api.privy.io/v1';
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;
let utf8Encoder: ReturnType<typeof getUtf8Encoder> | undefined;

/**
 * Configuration for creating a PrivySigner
 */
export interface PrivySignerConfig {
    /** Optional custom API base URL (defaults to https://api.privy.io/v1) */
    apiBaseUrl?: string;
    /** Privy application ID */
    appId: string;
    /** Privy application secret */
    appSecret: string;
    /**
     * Optional Privy wallet authorization context.
     *
     * Mirrors the lightweight parts of Privy's SDK AuthorizationContext:
     * authorization_private_keys, signatures, and sign_fns. JWT exchange is intentionally
     * left to caller-provided sign_fns so this package can stay REST-only and lightweight.
     */
    authorizationContext?: PrivyAuthorizationConfig;
    /**
     * Request-expiry window in milliseconds for authorization signatures.
     * Defaults to 15 minutes when authorizationContext is configured. Set to null to omit it.
     */
    authorizationRequestExpiryMs?: number | null;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
    /** Privy wallet ID */
    walletId: string;
}

type ResolvedPrivySignerConfig = PrivySignerConfig & {
    apiBaseUrl: string;
    authorizationRequestExpiryMs: number | null;
    requestDelayMs: number;
};

/**
 * Privy-based signer using Privy's wallet API
 *
 * Note: Must initialize with create() to fetch the public key
 *
 * @deprecated Prefer `createPrivySigner()`. Class export will be removed in a future version.
 */
export class PrivySigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly appId: string;
    private readonly appSecret: string;
    private readonly walletId: string;
    private readonly apiBaseUrl: string;
    private readonly authorizationContext: PrivyAuthorizationConfig | undefined;
    private readonly authorizationRequestExpiryMs: number | null;
    private readonly requestDelayMs: number;

    private constructor(config: ResolvedPrivySignerConfig, address: Address<TAddress>) {
        this.address = address;
        this.appId = config.appId;
        this.appSecret = config.appSecret;
        this.walletId = config.walletId;
        this.apiBaseUrl = config.apiBaseUrl;
        this.authorizationContext = config.authorizationContext;
        this.authorizationRequestExpiryMs = config.authorizationRequestExpiryMs;
        this.requestDelayMs = config.requestDelayMs;
    }

    /**
     * Create and initialize a PrivySigner
     * Fetches the public key from Privy API during initialization
     * @deprecated Use `createPrivySigner()` instead.
     */
    static async create<TAddress extends string = string>(config: PrivySignerConfig): Promise<PrivySigner<TAddress>> {
        if (!config.appId || !config.appSecret || !config.walletId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required configuration fields (appId, appSecret, or walletId)',
            });
        }
        const apiBaseUrl = config.apiBaseUrl || DEFAULT_API_BASE_URL;
        validateHttpsApiBaseUrl(apiBaseUrl);
        const requestDelayMs = config.requestDelayMs ?? 0;
        const authorizationRequestExpiryMs =
            config.authorizationRequestExpiryMs === undefined
                ? getDefaultPrivyAuthorizationRequestExpiryMs()
                : config.authorizationRequestExpiryMs;
        validateRequestDelayMs(requestDelayMs);
        validateAuthorizationRequestExpiryMs(authorizationRequestExpiryMs);

        const address = await fetchPublicKey<TAddress>({
            ...config,
            apiBaseUrl,
        });

        return new PrivySigner<TAddress>(
            {
                ...config,
                apiBaseUrl,
                authorizationRequestExpiryMs,
                requestDelayMs,
            },
            address,
        );
    }

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Get the signature bytes from a base64 encoded signature
     * @param signature - The base64 encoded signature
     * @returns The signature bytes
     */
    private getSignatureBytes(signature: SignatureBytesBase64): SignatureBytes {
        const encoder = getBase64Encoder();
        const signatureBytes = encoder.encode(signature) as SignatureBytes;
        return signatureBytes;
    }

    /**
     * Sign a base64 encoded wire transaction using Privy API
     * @param base64WireTransaction - The base64 encoded wire transaction to sign
     * @returns The signed base64 encoded wire transaction
     */
    private async signTransaction(
        base64WireTransaction: Base64EncodedWireTransaction,
    ): Promise<Base64EncodedWireTransaction> {
        const url = `${this.apiBaseUrl}/wallets/${this.walletId}/rpc`;

        const request: SignTransactionRequest = {
            chain_type: 'solana',
            method: 'signTransaction',
            params: {
                encoding: 'base64',
                transaction: base64WireTransaction,
            },
        };
        const authorizationHeaders = await preparePrivyAuthorizationHeaders({
            appId: this.appId,
            authorizationContext: this.authorizationContext,
            body: request,
            method: 'POST',
            requestExpiryMs: this.authorizationRequestExpiryMs,
            url,
        });

        let response: Response;
        try {
            response = await fetch(url, {
                body: JSON.stringify(request),
                headers: {
                    Authorization: getAuthHeader(this.appId, this.appSecret),
                    'Content-Type': 'application/json',
                    'privy-app-id': this.appId,
                    ...authorizationHeaders,
                },
                method: 'POST',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Privy network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Privy API signing error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let signResponse: SignTransactionResponse;
        try {
            signResponse = (await response.json()) as SignTransactionResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Privy signing response',
            });
        }

        if (!signResponse.data?.signed_transaction) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signed_transaction in Privy response',
            });
        }

        return signResponse.data.signed_transaction;
    }

    /**
     * Sign a base64 encoded message using Privy API
     * @param base64EncodedMessage - The base64 encoded message to sign
     * @returns The signature bytes
     */
    private async signMessage(base64EncodedMessage: TransactionMessageBytesBase64): Promise<SignatureBytes> {
        const url = `${this.apiBaseUrl}/wallets/${this.walletId}/rpc`;

        const request: SignMessageRequest = {
            chain_type: 'solana',
            method: 'signMessage',
            params: {
                encoding: 'base64',
                message: base64EncodedMessage,
            },
        };
        const authorizationHeaders = await preparePrivyAuthorizationHeaders({
            appId: this.appId,
            authorizationContext: this.authorizationContext,
            body: request,
            method: 'POST',
            requestExpiryMs: this.authorizationRequestExpiryMs,
            url,
        });

        let response: Response;
        try {
            response = await fetch(url, {
                body: JSON.stringify(request),
                headers: {
                    Authorization: getAuthHeader(this.appId, this.appSecret),
                    'Content-Type': 'application/json',
                    'privy-app-id': this.appId,
                    ...authorizationHeaders,
                },
                method: 'POST',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Privy network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Privy API signing error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let signResponse: SignMessageResponse;
        try {
            signResponse = (await response.json()) as SignMessageResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Privy signing response',
            });
        }

        if (!signResponse.data?.signature) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Privy response',
            });
        }

        return this.getSignatureBytes(signResponse.data.signature);
    }

    /**
     * Sign multiple messages using Privy API
     * @param messages - The messages to sign
     * @returns The signature dictionaries
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                base64Decoder ||= getBase64Decoder();
                const base64EncodedMessage = base64Decoder.decode(message.content) as TransactionMessageBytesBase64;
                const signatureBytes = await this.signMessage(base64EncodedMessage);
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
     * Sign multiple transactions using Privy API
     * @param transactions - The transactions to sign
     * @returns The signature dictionaries
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const wireTransaction = getBase64EncodedWireTransaction(transaction);
                const signedTx = await this.signTransaction(wireTransaction);
                const sigDict = extractSignatureFromWireTransaction({
                    base64WireTransaction: signedTx,
                    signerAddress: this.address,
                });
                await assertSignatureValid({
                    data: transaction.messageBytes,
                    signature: sigDict[this.address],
                    signerAddress: this.address,
                });
                return sigDict;
            }),
        );
    }

    /**
     * Check if the Privy signer is available
     * @returns True if the Privy signer is available, false otherwise
     */
    async isAvailable(): Promise<boolean> {
        try {
            await fetchPublicKey({
                apiBaseUrl: this.apiBaseUrl,
                appId: this.appId,
                appSecret: this.appSecret,
                walletId: this.walletId,
            });
            return true;
        } catch {
            return false;
        }
    }
}

function getAuthHeader(appId: string, appSecret: string): string {
    utf8Encoder ||= getUtf8Encoder();
    base64Decoder ||= getBase64Decoder();
    const credentials = `${appId}:${appSecret}`;
    const credentialsBytes = utf8Encoder.encode(credentials);
    return `Basic ${base64Decoder.decode(credentialsBytes)}`;
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

function validateRequestDelayMs(requestDelayMs: number): void {
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

function validateAuthorizationRequestExpiryMs(authorizationRequestExpiryMs: number | null): void {
    if (authorizationRequestExpiryMs !== null && authorizationRequestExpiryMs < 0) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'authorizationRequestExpiryMs must not be negative',
        });
    }
}

async function fetchPublicKey<TAddress extends string = string>(config: {
    apiBaseUrl?: string;
    appId: string;
    appSecret: string;
    walletId: string;
}): Promise<Address<TAddress>> {
    const apiBaseUrl = config.apiBaseUrl || DEFAULT_API_BASE_URL;
    const url = `${apiBaseUrl}/wallets/${config.walletId}`;

    let response: Response;
    try {
        response = await fetch(url, {
            headers: {
                Authorization: getAuthHeader(config.appId, config.appSecret),
                'privy-app-id': config.appId,
            },
            method: 'GET',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Privy network request failed',
            url,
        });
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Privy API error: ${response.status}`,
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    let walletInfo: WalletResponse<TAddress>;
    try {
        walletInfo = (await response.json()) as WalletResponse<TAddress>;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Privy response',
        });
    }

    if (!walletInfo.address) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: 'Missing address in Privy wallet response',
        });
    }

    if (walletInfo.chain_type !== 'solana') {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Expected Solana wallet, got chain_type=${walletInfo.chain_type}`,
        });
    }

    try {
        assertIsAddress(walletInfo.address);
    } catch (error) {
        throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
            cause: error,
            message: 'Invalid Solana address in Privy wallet response',
        });
    }
    return walletInfo.address;
}
