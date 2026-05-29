import { type Address, assertIsAddress } from '@solana/addresses';
import { getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    createSignerError,
    normalizePrivateKeyPem,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    type SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import type { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    getTransactionDecoder,
    type Transaction,
    type TransactionWithinSizeLimit,
    type TransactionWithLifetime,
} from '@solana/transactions';
import { importPKCS8, SignJWT } from 'jose';

import type {
    UtilaInitiateTransactionRequest,
    UtilaSignerConfig,
    UtilaTransaction,
    UtilaTransactionEnvelope,
    UtilaWalletResponse,
} from './types.js';

type ImportedPrivateKey = Awaited<ReturnType<typeof importPKCS8>>;
type ReadonlyBytes = ArrayLike<number> & { readonly byteLength: number };

const DEFAULT_API_BASE_URL = 'https://api.utila.io';
const UTILA_API_AUDIENCE = 'https://api.utila.io/';
const DEFAULT_POLL_INTERVAL_MS = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS = 60;
const TOKEN_TTL = '55m';

const TERMINAL_FAILURE_STATES = new Set([
    'DECLINED_BY_AML_POLICY',
    'MINED_FAILED',
    'FAILED',
    'DECLINED',
    'REPLACED',
    'CANCELED',
    'DROPPED',
    'EXPIRED',
]);

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;

/**
 * Create and initialize a Utila-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`,
 * `SIGNER_PARSING_ERROR`, or `SIGNER_INVALID_PUBLIC_KEY` when initialization fails.
 */
export async function createUtilaSigner<TAddress extends string = string>(
    config: UtilaSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await UtilaSigner.create(config);
}

export async function createUtilaAccessToken(
    serviceAccountEmail: string,
    privateKey: ImportedPrivateKey,
): Promise<string> {
    try {
        return await new SignJWT({})
            .setProtectedHeader({ alg: 'RS256' })
            .setSubject(serviceAccountEmail)
            .setAudience(UTILA_API_AUDIENCE)
            .setExpirationTime(TOKEN_TTL)
            .sign(privateKey);
    } catch (error) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            cause: error,
            message: 'Failed to create Utila access token',
        });
    }
}

/**
 * Utila-backed signer for Solana transactions.
 *
 * @deprecated Prefer `createUtilaSigner()`. Class export will be removed in a future version.
 */
export class UtilaSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiBaseUrl: string;
    private readonly designatedSigners: readonly string[];
    private readonly maxPollAttempts: number;
    private readonly network: string;
    private readonly pollIntervalMs: number;
    private readonly serviceAccountEmail: string;
    private readonly serviceAccountPrivateKey: ImportedPrivateKey;
    private readonly vaultId: string;
    private readonly walletId: string;

    static async create<TAddress extends string = string>(config: UtilaSignerConfig): Promise<UtilaSigner<TAddress>> {
        validateRequired('serviceAccountEmail', config.serviceAccountEmail);
        validateRequired('serviceAccountPrivateKeyPem', config.serviceAccountPrivateKeyPem);
        validateRequired('vaultId', config.vaultId);
        validateRequired('walletId', config.walletId);
        validateRequired('network', config.network);

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_API_BASE_URL);
        validateHttpsApiBaseUrl(apiBaseUrl);

        const pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        if (pollIntervalMs <= 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'pollIntervalMs must be greater than 0',
            });
        }

        const maxPollAttempts = config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS;
        if (maxPollAttempts <= 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'maxPollAttempts must be greater than 0',
            });
        }

        let privateKey: ImportedPrivateKey;
        try {
            const pem = normalizePrivateKeyPem(config.serviceAccountPrivateKeyPem);
            privateKey = await importPKCS8(pem, 'RS256');
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
                cause: error,
                message: 'Failed to parse Utila service account RSA private key',
            });
        }

        const vaultId = trimResourcePrefix(config.vaultId, 'vaults/');
        const walletId = trimWalletId(config.walletId);
        const designatedSigners = config.designatedSigners ?? [`users/${config.serviceAccountEmail}`];
        const wallet = await fetchWallet({
            apiBaseUrl,
            privateKey,
            serviceAccountEmail: config.serviceAccountEmail,
            vaultId,
            walletId,
        });
        const address = wallet?.wallet?.solanaDetails?.address;
        if (!address) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                message: 'Utila wallet response missing solanaDetails.address',
            });
        }

        try {
            assertIsAddress(address);
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Invalid Solana address from Utila wallet response',
            });
        }

        return new UtilaSigner<TAddress>({
            address: address as Address<TAddress>,
            apiBaseUrl,
            designatedSigners,
            maxPollAttempts,
            network: config.network,
            pollIntervalMs,
            privateKey,
            serviceAccountEmail: config.serviceAccountEmail,
            vaultId,
            walletId,
        });
    }

    private constructor(config: {
        address: Address<TAddress>;
        apiBaseUrl: string;
        designatedSigners: readonly string[];
        maxPollAttempts: number;
        network: string;
        pollIntervalMs: number;
        privateKey: ImportedPrivateKey;
        serviceAccountEmail: string;
        vaultId: string;
        walletId: string;
    }) {
        this.address = config.address;
        this.apiBaseUrl = config.apiBaseUrl;
        this.designatedSigners = config.designatedSigners;
        this.maxPollAttempts = config.maxPollAttempts;
        this.network = config.network;
        this.pollIntervalMs = config.pollIntervalMs;
        this.serviceAccountEmail = config.serviceAccountEmail;
        this.serviceAccountPrivateKey = config.privateKey;
        this.vaultId = config.vaultId;
        this.walletId = config.walletId;
    }

    async signMessages(_messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.reject(
            createSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Utila signMessages is not supported for Solana wallets in this signer',
            }),
        );
    }

    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(transactions.map(transaction => this.signTransactionWithUtila(transaction)));
    }

    async isAvailable(): Promise<boolean> {
        try {
            await fetchWallet({
                apiBaseUrl: this.apiBaseUrl,
                privateKey: this.serviceAccountPrivateKey,
                serviceAccountEmail: this.serviceAccountEmail,
                vaultId: this.vaultId,
                walletId: this.walletId,
            });
            return true;
        } catch {
            return false;
        }
    }

    private async signTransactionWithUtila(
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<SignatureDictionary> {
        const rawTransaction = getBase64EncodedWireTransaction(transaction);
        const initiated = await this.initiateTransaction(rawTransaction);
        const signed = await this.pollSignedTransaction(initiated);
        const rawSignedTransaction = signed.solanaTransaction?.rawTransaction;
        if (!rawSignedTransaction) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Utila signed transaction response missing solanaTransaction.rawTransaction',
            });
        }

        return await this.extractSignatureFromRawTransaction(rawSignedTransaction, transaction.messageBytes);
    }

    private async initiateTransaction(rawTransaction: string): Promise<UtilaTransaction> {
        const body: UtilaInitiateTransactionRequest = {
            designatedSigners: this.designatedSigners,
            details: {
                solanaSerializedTransaction: {
                    network: this.network,
                    publish: false,
                    rawTransaction,
                    replaceBlockhash: false,
                    tryReplaceBlockhash: false,
                },
            },
        };

        const response = await this.request<UtilaTransactionEnvelope>(
            `/v2/vaults/${encodeURIComponent(this.vaultId)}/transactions:initiate`,
            'POST',
            body,
        );
        return parseTransactionEnvelope(response, 'initiate transaction');
    }

    private async getTransaction(transactionId: string): Promise<UtilaTransaction> {
        const response = await this.request<UtilaTransactionEnvelope>(
            `/v2/vaults/${encodeURIComponent(this.vaultId)}/transactions/${encodeURIComponent(transactionId)}?view=FULL`,
            'GET',
        );
        return parseTransactionEnvelope(response, 'get transaction');
    }

    private async pollSignedTransaction(transaction: UtilaTransaction): Promise<UtilaTransaction> {
        let current = transaction;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            if (current.state === 'SIGNED') {
                return current;
            }
            if (current.state && TERMINAL_FAILURE_STATES.has(current.state)) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Utila transaction reached terminal state ${current.state}`,
                });
            }

            await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
            current = await this.getTransaction(extractTransactionId(current.name));
        }

        if (current.state === 'SIGNED') {
            return current;
        }
        if (current.state && TERMINAL_FAILURE_STATES.has(current.state)) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Utila transaction reached terminal state ${current.state}`,
            });
        }

        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Utila transaction polling timed out after ${this.maxPollAttempts} attempts`,
        });
    }

    private async request<T>(path: string, method: 'GET' | 'POST', body?: unknown): Promise<T> {
        const url = `${this.apiBaseUrl}${path}`;
        const token = await createUtilaAccessToken(this.serviceAccountEmail, this.serviceAccountPrivateKey);
        const headers: Record<string, string> = {
            Authorization: `Bearer ${token}`,
        };
        if (body != null) {
            headers['Content-Type'] = 'application/json';
        }

        let response: Response;
        try {
            response = await fetch(url, {
                body: body != null ? JSON.stringify(body) : undefined,
                headers,
                method,
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Utila network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Utila API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        try {
            return (await response.json()) as T;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Utila response',
            });
        }
    }

    private async extractSignatureFromRawTransaction(
        rawTransaction: string,
        expectedMessageBytes: ReadonlyBytes,
    ): Promise<SignatureDictionary> {
        base64Encoder ||= getBase64Encoder();
        let decodedTransaction: Transaction;
        try {
            const transactionBytes = base64Encoder.encode(rawTransaction);
            decodedTransaction = getTransactionDecoder().decode(transactionBytes);
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Utila signed transaction',
            });
        }

        if (!bytesEqual(decodedTransaction.messageBytes, expectedMessageBytes)) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Utila returned a signed transaction with different message bytes',
            });
        }

        const signature = decodedTransaction.signatures[this.address];
        if (!signature) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: `No signature found for address ${this.address}`,
            });
        }

        await assertSignatureValid({
            data: new Uint8Array(expectedMessageBytes),
            signature,
            signerAddress: this.address,
        });
        return createSignatureDictionary({ signature, signerAddress: this.address });
    }
}

async function fetchWallet({
    apiBaseUrl,
    privateKey,
    serviceAccountEmail,
    vaultId,
    walletId,
}: {
    apiBaseUrl: string;
    privateKey: ImportedPrivateKey;
    serviceAccountEmail: string;
    vaultId: string;
    walletId: string;
}): Promise<UtilaWalletResponse> {
    const url = `${apiBaseUrl}/v2/vaults/${encodeURIComponent(vaultId)}/wallets/${encodeURIComponent(walletId)}`;
    const token = await createUtilaAccessToken(serviceAccountEmail, privateKey);

    let response: Response;
    try {
        response = await fetch(url, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
            method: 'GET',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Utila network request failed',
            url,
        });
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Utila API error: ${response.status}`,
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    try {
        return (await response.json()) as UtilaWalletResponse;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Utila wallet response',
        });
    }
}

function parseTransactionEnvelope(payload: UtilaTransactionEnvelope, context: string): UtilaTransaction {
    const transaction = payload?.transaction;
    if (!transaction?.name || !transaction.state) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Failed to ${context}: missing transaction name/state`,
        });
    }
    return transaction;
}

function extractTransactionId(name?: string): string {
    const parts = name?.split('/').filter(Boolean) ?? [];
    const transactionId = parts[parts.length - 1];
    if (!transactionId) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: 'Utila transaction response missing transaction id',
        });
    }
    return transactionId;
}

function validateRequired(field: string, value: string | undefined): void {
    if (!value?.trim()) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Missing required ${field} field`,
        });
    }
}

function normalizeBaseUrl(baseUrl: string): string {
    return baseUrl.replace(/\/+$/, '');
}

function validateHttpsApiBaseUrl(apiBaseUrl: string): void {
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(apiBaseUrl);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: `Invalid apiBaseUrl: ${apiBaseUrl}`,
        });
    }
    if (parsedUrl.protocol !== 'https:') {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'apiBaseUrl must use HTTPS',
        });
    }
}

function trimResourcePrefix(value: string, prefix: string): string {
    return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

function trimWalletId(value: string): string {
    const marker = '/wallets/';
    const markerIndex = value.lastIndexOf(marker);
    return markerIndex === -1 ? value : value.slice(markerIndex + marker.length);
}

function bytesEqual(a: ReadonlyBytes, b: ReadonlyBytes): boolean {
    if (a.byteLength !== b.byteLength) return false;
    for (let i = 0; i < a.byteLength; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
