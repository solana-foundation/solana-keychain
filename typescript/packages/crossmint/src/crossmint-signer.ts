import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Encoder, getBase58Decoder, getBase58Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    createSignerError,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    normalizeBaseUrl,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
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

/**
 * Crossmint is a broadcast-managed signer: it rewrites the transaction (gas
 * sponsorship, priority fee, its own blockhash) and broadcasts server-side, so
 * returned signatures cover Crossmint's bytes, not the caller's `messageBytes`.
 */
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
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

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
        validateRequestDelayMs(requestDelayMs);

        let signerSeed: Uint8Array | undefined;
        let signer = config.signer;
        if (config.signerSecret) {
            signerSeed = await deriveSignerSeed(config.signerSecret, config.apiKey);
            if (!signer) {
                base58Decoder ||= getBase58Decoder();
                signer = `server:${base58Decoder.decode(await ed25519PublicKeyFromSeed(signerSeed))}`;
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
            const pending = this.findPendingApprovalForSigner(response);
            if (
                response.status === 'awaiting-approval' &&
                this.signerSeed &&
                this.signer &&
                !approvalSubmitted &&
                pending !== undefined
            ) {
                response = await this.submitApproval(response, pending);
                approvalSubmitted = true;
                // Re-evaluate the new status immediately; approvalSubmitted
                // ensures the approval is signed and submitted at most once.
                continue;
            }
            const terminalSignature = await this.resolveTerminalStatus(response, transaction, approvalSubmitted);
            if (terminalSignature) {
                return terminalSignature;
            }

            await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
            response = await this.getTransaction(response.id);
        }

        const terminalSignature = await this.resolveTerminalStatus(response, transaction, approvalSubmitted);
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
        approvalSubmitted: boolean,
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
                // Crossmint may register a submitted approval asynchronously, so
                // awaiting-approval is only terminal while no approval of ours is
                // in flight; otherwise keep polling until the status advances.
                if (approvalSubmitted) {
                    return undefined;
                }
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
    ): { message?: string; signer?: { locator?: string } } | undefined {
        // The response-side signer is a nested object; match on its `locator`
        // string (the same value we submit as `signer` when approving).
        return response.approvals?.pending?.find(entry => entry.signer?.locator === this.signer);
    }

    private async submitApproval(
        response: CrossmintTransactionResponse,
        pending: { message?: string; signer?: { locator?: string } },
    ): Promise<CrossmintTransactionResponse> {
        const message = pending.message;
        if (!message) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Crossmint transaction awaiting approval but no pending message found',
            });
        }

        base58Encoder ||= getBase58Encoder();
        const messageBytes = new Uint8Array(base58Encoder.encode(message));
        const signatureBytes = await ed25519Sign(this.signerSeed!, messageBytes);

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

        return await fetchSignerJson<unknown>({
            init: {
                body: body != null ? JSON.stringify(body) : undefined,
                headers,
                method,
            },
            providerName: 'Crossmint',
            url,
        });
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

        // Verify against the bytes Crossmint actually signed, not the caller's
        // messageBytes: Crossmint rewrites the tx (blockhash/fees) before signing,
        // so a strict check against caller bytes would reject legitimately landed txs.
        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature,
            signerAddress: this.address,
        });
        return signature;
    }
}

async function fetchWallet(
    apiBaseUrl: string,
    apiKey: string,
    walletLocator: string,
): Promise<CrossmintWalletResponse> {
    const url = `${apiBaseUrl}/${API_VERSION}/wallets/${encodeURIComponent(walletLocator)}`;
    const wallet = await fetchSignerJson<Partial<CrossmintWalletResponse>>({
        init: {
            headers: {
                'X-API-KEY': apiKey,
            },
            method: 'GET',
        },
        providerName: 'Crossmint',
        url,
    });

    if (!wallet.address || !wallet.chainType || !wallet.type) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: 'Crossmint wallet response missing required fields (address, chainType, type)',
        });
    }

    return wallet as CrossmintWalletResponse;
}

function parseTransactionResponse(payload: unknown, context: string): CrossmintTransactionResponse {
    const transaction = payload as Partial<CrossmintTransactionResponse>;
    if (!transaction.id || !transaction.status) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Failed to ${context}: missing transaction id/status`,
        });
    }
    return transaction as CrossmintTransactionResponse;
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

async function deriveSignerSeed(secret: string, apiKey: string): Promise<Uint8Array> {
    const { hkdfSync } = await import('node:crypto');
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

async function ed25519PublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
    const { createPrivateKey, createPublicKey } = await import('node:crypto');
    const privateKey = createPrivateKey({
        format: 'der',
        key: buildPkcs8Der(seed),
        type: 'pkcs8',
    });
    const spki = createPublicKey(privateKey as unknown as Parameters<typeof createPublicKey>[0]).export({
        format: 'der',
        type: 'spki',
    }) as Buffer;
    return new Uint8Array(spki.slice(-32));
}

async function ed25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    const { createPrivateKey, sign: cryptoSign } = await import('node:crypto');
    const privateKey = createPrivateKey({
        format: 'der',
        key: buildPkcs8Der(seed),
        type: 'pkcs8',
    });
    return new Uint8Array(cryptoSign(null, Buffer.from(message), privateKey));
}

function stringifyError(error: unknown): string {
    if (typeof error === 'string') return sanitizeRemoteErrorResponse(error);
    if (typeof error === 'number' || typeof error === 'boolean' || typeof error === 'bigint') {
        return String(error);
    }
    if (error instanceof Error) {
        return sanitizeRemoteErrorResponse(error.message);
    }
    if (error == null) return 'unknown error';
    try {
        return sanitizeRemoteErrorResponse(JSON.stringify(error));
    } catch {
        return 'unknown error';
    }
}
