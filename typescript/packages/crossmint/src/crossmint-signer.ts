import { Address, assertIsAddress } from '@solana/addresses';
import { getBase58Decoder, getBase58Encoder, getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    createSignerError,
    extractSignatureFromWireTransaction,
    SignerError,
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
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type {
    CrossmintApiError,
    CrossmintCreateTransactionRequest,
    CrossmintSignerConfig,
    CrossmintTransactionResponse,
    CrossmintTransactionStatus,
    CrossmintWalletResponse,
} from './types.js';

export async function createCrossmintSigner<TAddress extends string = string>(
    config: CrossmintSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await CrossmintSigner.create(config);
}

const API_VERSION = '2025-06-09';
const DEFAULT_API_BASE_URL = 'https://www.crossmint.com/api';
const DEFAULT_POLL_INTERVAL_MS = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS = 60;

let base58Decoder: ReturnType<typeof getBase58Decoder> | undefined;
let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;
let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;

class CrossmintSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiKey: string;
    private readonly walletLocator: string;
    private readonly apiBaseUrl: string;
    private readonly pollIntervalMs: number;
    private readonly maxPollAttempts: number;
    private readonly requestDelayMs: number;
    private readonly signer?: string;

    private constructor(config: {
        address: Address<TAddress>;
        apiBaseUrl: string;
        apiKey: string;
        maxPollAttempts: number;
        pollIntervalMs: number;
        requestDelayMs: number;
        signer?: string;
        walletLocator: string;
    }) {
        this.address = config.address;
        this.apiKey = config.apiKey;
        this.walletLocator = config.walletLocator;
        this.apiBaseUrl = config.apiBaseUrl;
        this.pollIntervalMs = config.pollIntervalMs;
        this.maxPollAttempts = config.maxPollAttempts;
        this.requestDelayMs = config.requestDelayMs;
        this.signer = config.signer;
    }

    static async create<TAddress extends string = string>(
        config: CrossmintSignerConfig,
    ): Promise<CrossmintSigner<TAddress>> {
        if (!config.apiKey) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required apiKey field',
            });
        }
        if (!config.walletLocator) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required walletLocator field',
            });
        }

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_API_BASE_URL);
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

        const requestDelayMs = config.requestDelayMs ?? 0;
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

        const wallet = await fetchWallet(apiBaseUrl, config.apiKey, config.walletLocator);
        if (wallet.chainType.toLowerCase() !== 'solana') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Expected Solana wallet, got chainType=${wallet.chainType}`,
            });
        }
        if (wallet.type.toLowerCase() !== 'smart' && wallet.type.toLowerCase() !== 'mpc') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unsupported Crossmint wallet type: ${wallet.type}`,
            });
        }

        let address: Address<TAddress>;
        try {
            assertIsAddress(wallet.address);
            address = wallet.address as Address<TAddress>;
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Invalid Solana address from Crossmint wallet response',
            });
        }

        return new CrossmintSigner<TAddress>({
            address,
            apiBaseUrl,
            apiKey: config.apiKey,
            maxPollAttempts,
            pollIntervalMs,
            requestDelayMs,
            signer: config.signer,
            walletLocator: config.walletLocator,
        });
    }

    async signMessages(_messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.reject(
            createSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Crossmint signMessages is not supported for Solana wallets in this signer',
            }),
        );
    }

    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                if (this.requestDelayMs > 0 && index > 0) {
                    await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
                }
                const signature = await this.signTransactionManaged(transaction);
                await assertSignatureValid({
                    data: transaction.messageBytes,
                    signature,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature,
                    signerAddress: this.address,
                });
            }),
        );
    }

    async isAvailable(): Promise<boolean> {
        try {
            await fetchWallet(this.apiBaseUrl, this.apiKey, this.walletLocator);
            return true;
        } catch {
            return false;
        }
    }

    private async signTransactionManaged(
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<SignatureBytes> {
        let response = await this.createTransaction(transaction);

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const terminalSignature = this.resolveTerminalStatus(response);
            if (terminalSignature) {
                return terminalSignature;
            }

            await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
            response = await this.getTransaction(response.id);
        }

        const terminalSignature = this.resolveTerminalStatus(response);
        if (terminalSignature) {
            return terminalSignature;
        }

        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Crossmint transaction polling timed out after ${this.maxPollAttempts} attempts`,
        });
    }

    private resolveTerminalStatus(response: CrossmintTransactionResponse): SignatureBytes | undefined {
        const status = response.status as CrossmintTransactionStatus;
        switch (status) {
            case 'success':
                return this.extractSignature(response);
            case 'failed':
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Crossmint transaction failed: ${stringifyError(response.error)}`,
                });
            case 'awaiting-approval':
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: 'Crossmint transaction is awaiting approval; additional signer approvals are required',
                });
            case 'pending':
            default:
                return undefined;
        }
    }

    private async createTransaction(
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<CrossmintTransactionResponse> {
        const wireTransaction = getBase64EncodedWireTransaction(transaction);
        base64Encoder ||= getBase64Encoder();
        const transactionBytes = base64Encoder.encode(wireTransaction);
        base58Decoder ||= getBase58Decoder();
        const transactionBase58 = base58Decoder.decode(transactionBytes);

        const body: CrossmintCreateTransactionRequest = {
            params: {
                transaction: transactionBase58,
                ...(this.signer ? { signer: this.signer } : {}),
            },
        };

        const path = `/${API_VERSION}/wallets/${encodeURIComponent(this.walletLocator)}/transactions`;
        const response = await this.request(path, 'POST', body);
        return parseTransactionResponse(response, 'create transaction');
    }

    private async getTransaction(transactionId: string): Promise<CrossmintTransactionResponse> {
        const path = `/${API_VERSION}/wallets/${encodeURIComponent(this.walletLocator)}/transactions/${encodeURIComponent(transactionId)}`;
        const response = await this.request(path, 'GET');
        return parseTransactionResponse(response, 'get transaction');
    }

    private async request(path: string, method: 'GET' | 'POST', body?: unknown): Promise<unknown> {
        const url = `${this.apiBaseUrl}${path}`;
        const headers: Record<string, string> = {
            'X-API-KEY': this.apiKey,
        };
        if (method === 'POST' && body != null) {
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
                message: 'Crossmint network request failed',
                url,
            });
        }

        let payload: unknown;
        try {
            payload = await response.json();
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Crossmint response',
            });
        }

        if (!response.ok) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: extractApiErrorMessage(payload, `Crossmint API error: ${response.status}`),
                status: response.status,
            });
        }

        return payload;
    }

    private extractSignature(response: CrossmintTransactionResponse): SignatureBytes {
        const fromSerialized = this.extractSignatureFromSerializedTransaction(response.onChain?.transaction);
        if (fromSerialized) {
            return fromSerialized;
        }

        const fromTxId = decodeSignatureString(response.onChain?.txId);
        if (fromTxId) {
            return fromTxId;
        }

        const submitted = response.approvals?.submitted ?? [];
        for (const approval of submitted) {
            const signature = decodeSignatureString(approval.signature);
            if (signature) {
                return signature;
            }
        }

        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: 'Unable to extract signature from Crossmint transaction response',
        });
    }

    private extractSignatureFromSerializedTransaction(serializedTransaction?: string): SignatureBytes | undefined {
        if (!serializedTransaction) return undefined;

        try {
            base58Encoder ||= getBase58Encoder();
            const txBytes = base58Encoder.encode(serializedTransaction);
            base64Decoder ||= getBase64Decoder();
            const base64WireTransaction = base64Decoder.decode(txBytes) as Base64EncodedWireTransaction;
            const signatureDict = extractSignatureFromWireTransaction({
                base64WireTransaction,
                signerAddress: this.address,
            });

            return signatureDict[this.address];
        } catch (error) {
            if (error instanceof SignerError) {
                throw error;
            }
            return undefined;
        }
    }
}

function normalizeBaseUrl(baseUrl: string): string {
    return baseUrl.replace(/\/+$/, '');
}

async function fetchWallet(
    apiBaseUrl: string,
    apiKey: string,
    walletLocator: string,
): Promise<CrossmintWalletResponse> {
    const url = `${apiBaseUrl}/${API_VERSION}/wallets/${encodeURIComponent(walletLocator)}`;
    let response: Response;
    try {
        response = await fetch(url, {
            headers: {
                'X-API-KEY': apiKey,
            },
            method: 'GET',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Crossmint network request failed',
            url,
        });
    }

    let payload: unknown;
    try {
        payload = await response.json();
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Crossmint wallet response',
        });
    }

    if (!response.ok) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: extractApiErrorMessage(payload, `Crossmint API error: ${response.status}`),
            status: response.status,
        });
    }

    const wallet = payload as Partial<CrossmintWalletResponse>;
    if (!wallet.address || !wallet.chainType || !wallet.type) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: extractApiErrorMessage(payload, 'Crossmint wallet response missing required fields (address, chainType, type)'),
        });
    }

    return wallet as CrossmintWalletResponse;
}

function parseTransactionResponse(payload: unknown, context: string): CrossmintTransactionResponse {
    const transaction = payload as Partial<CrossmintApiError> & Partial<CrossmintTransactionResponse>;
    if (!transaction.id || !transaction.status) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: extractApiErrorMessage(payload, `Failed to ${context}: missing transaction id/status`),
        });
    }
    return transaction as CrossmintTransactionResponse;
}

function extractApiErrorMessage(payload: unknown, fallback: string): string {
    if (payload && typeof payload === 'object') {
        const obj = payload as Record<string, unknown>;
        if (typeof obj.message === 'string') return obj.message;
        if (typeof obj.error === 'string') return obj.error;
        if (obj.error && typeof obj.error === 'object') {
            const errorObj = obj.error as Record<string, unknown>;
            if (typeof errorObj.message === 'string') return errorObj.message;
        }
    }
    return fallback;
}

function decodeSignatureString(value?: string): SignatureBytes | undefined {
    if (!value) return undefined;

    base58Encoder ||= getBase58Encoder();
    try {
        const bytes = base58Encoder.encode(value);
        if (bytes.length === 64) {
            return bytes as SignatureBytes;
        }
    } catch {
        // Try next codec
    }

    if (/^(0x)?[0-9a-fA-F]{128}$/.test(value)) {
        const clean = value.startsWith('0x') ? value.slice(2) : value;
        const bytes = new Uint8Array(64);
        for (let i = 0; i < 64; i++) {
            bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes as SignatureBytes;
    }

    base64Encoder ||= getBase64Encoder();
    try {
        const bytes = base64Encoder.encode(value);
        if (bytes.length === 64) {
            return bytes as SignatureBytes;
        }
    } catch {
        // no-op
    }

    return undefined;
}

function stringifyError(error: unknown): string {
    if (typeof error === 'string') return error;
    if (typeof error === 'number' || typeof error === 'boolean' || typeof error === 'bigint') {
        return String(error);
    }
    if (error instanceof Error) {
        return error.message;
    }
    if (error == null) return 'unknown error';
    try {
        return JSON.stringify(error);
    } catch {
        return 'unknown error';
    }
}
