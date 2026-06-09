import { createPrivateKey, createPublicKey, hkdfSync, sign as cryptoSign } from 'node:crypto';

import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Encoder, getBase58Decoder, getBase58Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    createSignerError,
    ED25519_SIGNATURE_LENGTH,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    getTransactionDecoder,
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

let base16Encoder: ReturnType<typeof getBase16Encoder> | undefined;
let base58Decoder: ReturnType<typeof getBase58Decoder> | undefined;
let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
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

    private readonly signerSeed?: Uint8Array;

    private constructor(config: {
        address: Address<TAddress>;
        apiBaseUrl: string;
        apiKey: string;
        maxPollAttempts: number;
        pollIntervalMs: number;
        requestDelayMs: number;
        signer?: string;
        signerSeed?: Uint8Array;
        walletLocator: string;
    }) {
        this.address = config.address;
        this.apiKey = config.apiKey;
        this.walletLocator = config.walletLocator;
        this.apiBaseUrl = config.apiBaseUrl;
        this.pollIntervalMs = config.pollIntervalMs;
        this.maxPollAttempts = config.maxPollAttempts;
        this.requestDelayMs = config.requestDelayMs;
        this.signerSeed = config.signerSeed;
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

        let signerSeed: Uint8Array | undefined;
        let signer = config.signer;
        if (config.signerSecret) {
            signerSeed = deriveSignerSeed(config.signerSecret, config.apiKey);
            if (!signer) {
                base58Decoder ||= getBase58Decoder();
                signer = `server:${base58Decoder.decode(ed25519PublicKeyFromSeed(signerSeed))}`;
            }
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
            signer,
            signerSeed,
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
        // Sign sequentially, not via Promise.all: each transaction has
        // irreversible server-side effects (createTransaction, and auto-approval
        // when signerSecret is set). Concurrent submission means a failure in one
        // transaction would abandon siblings that Crossmint has already created
        // and may execute, leading to duplicate spends on retry. Sequential
        // execution stops on the first error before any further transaction is
        // created.
        const results: SignatureDictionary[] = [];
        for (const [index, transaction] of transactions.entries()) {
            if (this.requestDelayMs > 0 && index > 0) {
                await new Promise(resolve => setTimeout(resolve, this.requestDelayMs));
            }
            const signature = await this.signTransactionManaged(transaction);
            results.push(createSignatureDictionary({ signature, signerAddress: this.address }));
        }
        return results;
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
        let approvalSubmitted = false;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            if (
                response.status === 'awaiting-approval' &&
                this.signerSeed &&
                this.signer &&
                !approvalSubmitted &&
                this.findPendingApprovalForSigner(response) !== undefined
            ) {
                response = await this.submitApproval(response);
                approvalSubmitted = true;
                // Re-evaluate the new status immediately; the approvalSubmitted
                // guard prevents this branch from re-running, so we cannot
                // busy-loop re-signing/re-submitting the same approval.
                continue;
            }
            const terminalSignature = await this.resolveTerminalStatus(response, transaction);
            if (terminalSignature) {
                return terminalSignature;
            }

            await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
            response = await this.getTransaction(response.id);
        }

        const terminalSignature = await this.resolveTerminalStatus(response, transaction);
        if (terminalSignature) {
            return terminalSignature;
        }

        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Crossmint transaction polling timed out after ${this.maxPollAttempts} attempts`,
        });
    }

    private async resolveTerminalStatus(
        response: CrossmintTransactionResponse,
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<SignatureBytes | undefined> {
        const status = response.status as CrossmintTransactionStatus;
        switch (status) {
            case 'success':
                return await this.extractSignature(response, transaction);
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

    /**
     * Finds the pending approval entry that belongs to this signer's locator.
     * On a multi-approver wallet, `pending` may contain challenges for other
     * approvers; signing the wrong one with our key and submitting it under our
     * locator yields a vendor 4xx. Returns `undefined` when there is nothing for
     * us to approve.
     */
    private findPendingApprovalForSigner(
        response: CrossmintTransactionResponse,
    ): { message?: string; signer?: unknown } | undefined {
        return response.approvals?.pending?.find(entry => entry.signer === this.signer);
    }

    private async submitApproval(response: CrossmintTransactionResponse): Promise<CrossmintTransactionResponse> {
        const pending = this.findPendingApprovalForSigner(response);
        // Nothing pending for us: do not sign another approver's challenge.
        // Return the response unchanged so the caller falls through to
        // resolveTerminalStatus (which surfaces the awaiting-approval error).
        if (!pending) {
            return response;
        }

        const message = pending.message;
        if (!message) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Crossmint transaction awaiting approval but no pending message found',
            });
        }

        base58Encoder ||= getBase58Encoder();
        const messageBytes = new Uint8Array(base58Encoder.encode(message));
        const signatureBytes = ed25519Sign(this.signerSeed!, messageBytes);

        base58Decoder ||= getBase58Decoder();
        const signatureB58 = base58Decoder.decode(signatureBytes);

        const path = `/${API_VERSION}/wallets/${encodeURIComponent(this.walletLocator)}/transactions/${encodeURIComponent(response.id)}/approvals`;
        const result = await this.request(path, 'POST', {
            approvals: [{ signature: signatureB58, signer: this.signer }],
        });
        return parseTransactionResponse(result, 'submit approval');
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

    private async extractSignature(
        response: CrossmintTransactionResponse,
        transaction: Transaction & TransactionWithinSizeLimit & TransactionWithLifetime,
    ): Promise<SignatureBytes> {
        if (response.onChain?.transaction) {
            try {
                return await this.extractSignatureFromSerializedTransaction(response.onChain.transaction);
            } catch {
                // If Crossmint returned an onChain.transaction but it could not be
                // decoded or validated, fall through to txId and still require
                // cryptographic validation against the original message bytes.
            }
        }

        const fromTxId = decodeSignatureString(response.onChain?.txId);
        if (fromTxId) {
            await assertSignatureValid({
                data: transaction.messageBytes,
                signature: fromTxId,
                signerAddress: this.address,
            });
            return fromTxId;
        }

        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: 'Unable to extract signature from Crossmint transaction response',
        });
    }

    private async extractSignatureFromSerializedTransaction(serializedTransaction: string): Promise<SignatureBytes> {
        base58Encoder ||= getBase58Encoder();
        const txBytes = base58Encoder.encode(serializedTransaction);
        const decodedTransaction = getTransactionDecoder().decode(txBytes);

        const signature = decodedTransaction.signatures[this.address];
        if (!signature) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: `No signature found for address ${this.address}`,
            });
        }

        // Verify against the message bytes that Crossmint actually signed.
        // Crossmint may refresh the blockhash before signing, so these may
        // differ from the original transaction.messageBytes.
        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature,
            signerAddress: this.address,
        });
        return signature;
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
            message: extractApiErrorMessage(
                payload,
                'Crossmint wallet response missing required fields (address, chainType, type)',
            ),
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
        return bytes.length === ED25519_SIGNATURE_LENGTH ? (bytes as SignatureBytes) : undefined;
    } catch {
        return undefined;
    }
}

const PKCS8_ED25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function deriveSignerSeed(secret: string, apiKey: string): Uint8Array {
    const rawSecret = secret.startsWith('xmsk1_') ? secret.slice(6) : secret;
    if (rawSecret.length !== 64) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `signerSecret must be a 64-char hex string, got ${rawSecret.length} chars`,
        });
    }
    base16Encoder ||= getBase16Encoder();
    const ikm = Buffer.from(base16Encoder.encode(rawSecret));

    // Parse API key: {ck|sk}_{environment}_{base58data}
    // base58-decoded data is UTF-8: "projectId:nacl_signature"
    const parts = apiKey.split('_');
    const environment = parts[1];
    const base58Data = parts.slice(2).join('_');
    base58Encoder ||= getBase58Encoder();
    const decoded = base58Encoder.encode(base58Data);
    const projectId = new TextDecoder().decode(decoded).split(':')[0];

    const info = `${projectId}:${environment}:solana-ed25519`;
    return new Uint8Array(hkdfSync('sha256', ikm, 'crossmint', info, 32));
}

function buildPkcs8Der(seed: Uint8Array): Buffer {
    return Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
}

function ed25519PublicKeyFromSeed(seed: Uint8Array): Uint8Array {
    const privateKey = createPrivateKey({
        format: 'der',
        key: buildPkcs8Der(seed),
        type: 'pkcs8',
    });
    const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
    return new Uint8Array(spki.slice(-32));
}

function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
    const privateKey = createPrivateKey({
        format: 'der',
        key: buildPkcs8Der(seed),
        type: 'pkcs8',
    });
    return new Uint8Array(cryptoSign(null, Buffer.from(message), privateKey));
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
