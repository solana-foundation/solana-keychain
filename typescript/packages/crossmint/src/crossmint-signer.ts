import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Encoder, getBase58Decoder, getBase58Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    abortableDelay,
    assertHttpsUrl,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    idempotencyKeyFromMessage,
    normalizeBaseUrl,
    providerMayHaveAccepted,
    providerStatus,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSendingSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { TransactionSendingSignerConfig } from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    getTransactionDecoder,
    Transaction,
    TransactionWithLifetime,
} from '@solana/transactions';

import type {
    CrossmintCreateTransactionRequest,
    CrossmintSignerConfig,
    CrossmintTransactionResponse,
    CrossmintTransactionStatus,
    CrossmintWalletResponse,
} from './types.js';

/**
 * Crossmint signer shape.
 *
 * Crossmint rewrites transactions to sponsor gas, so the message it signs
 * generally differs from the caller's and its signatures cannot be applied to the
 * caller's transaction. Hence Kit's sending-signer flow rather than a partial
 * signer: no `signTransactions`, and no `signMessages` either — Crossmint does
 * not support message signing for Solana wallets, and Kit classifies signers by
 * method presence.
 */
export type CrossmintSendingSigner<TAddress extends string = string> = SolanaSendingSigner<TAddress>;

export async function createCrossmintSigner<TAddress extends string = string>(
    config: CrossmintSignerConfig,
): Promise<CrossmintSendingSigner<TAddress>> {
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
 * its signatures cover Crossmint's bytes, not the caller's `messageBytes`.
 * The returned value is the landed transaction's fee-payer signature, the
 * identifier Solana RPC looks it up by, which is why this signer implements
 * {@link SolanaSendingSigner} instead of returning signature dictionaries
 * keyed to the caller's message.
 *
 * Not retry-safe: any failure after the create is accepted rejects with
 * `BROADCAST_UNCONFIRMED` carrying `context.providerTransactionId`; check that
 * transaction with Crossmint before retrying. A create that fails without a
 * usable response rejects with `BROADCAST_UNCONFIRMED` and no
 * `providerTransactionId`.
 *
 * Each create carries an `x-idempotency-key` derived from the message bytes, so
 * replaying these exact bytes cannot create a second transaction; a rebuilt
 * transaction derives a different key and executes as a new transfer.
 */
class CrossmintSigner<TAddress extends string = string> implements CrossmintSendingSigner<TAddress> {
    // No signTransactions/signMessages: Kit classifies signers by duck-typed
    // method presence, so a present-but-throwing method would make Kit
    // partial-sign transactions (or collect message signatures) and fail at
    // runtime. See SolanaSendingSigner in @solana/keychain-core.
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
            base58Decoder ||= getBase58Decoder();
            const derived = base58Decoder.decode(await ed25519PublicKeyFromSeed(signerSeed)) as Address;
            if (!signer) {
                signer = `server:${derived}`;
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

    async signAndSendTransactions(
        transactions: readonly (Transaction | (Transaction & TransactionWithLifetime))[],
        config?: TransactionSendingSignerConfig,
    ): Promise<readonly SignatureBytes[]> {
        config?.abortSignal?.throwIfAborted();

        // Sign sequentially, not via Promise.all: each transaction has
        // irreversible server-side effects (createTransaction, and auto-approval
        // when signerSecret is set). Concurrent submission means a failure in one
        // transaction would abandon siblings that Crossmint has already created
        // and may execute, leading to duplicate spends on retry. Sequential
        // execution stops on the first error before any further transaction is
        // created.
        const results: SignatureBytes[] = [];
        for (const [index, transaction] of transactions.entries()) {
            if (this.requestDelayMs > 0 && index > 0) {
                await abortableDelay(this.requestDelayMs, config?.abortSignal);
            }
            config?.abortSignal?.throwIfAborted();
            results.push(await this.signTransactionManaged(transaction, config?.abortSignal));
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

    /**
     * `abortSignal` stops this client from waiting; it cannot recall work Crossmint
     * has already accepted, so an aborted transaction may still land server-side.
     */
    private async signTransactionManaged(transaction: Transaction, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        let created: CrossmintTransactionResponse;
        try {
            created = await this.createTransaction(transaction, abortSignal);
        } catch (error) {
            if (!providerMayHaveAccepted(error)) {
                throw error;
            }
            // Crossmint may be executing a transaction whose id never reached us.
            const status = providerStatus(error);
            return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                cause: error,
                message: 'Crossmint may have created the transaction, but no transaction id was returned',
                ...(status === undefined ? {} : { status }),
            });
        }
        // Post-create failures leave an outcome Crossmint may still execute, so
        // they surface as BROADCAST_UNCONFIRMED with the transaction id.
        try {
            return await this.driveTransactionToSignature(created, abortSignal);
        } catch (error) {
            return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                cause: error,
                message: `Crossmint may have executed the transaction, but the outcome could not be confirmed (provider transaction id: ${created.id})`,
                providerTransactionId: created.id,
            });
        }
    }

    private async driveTransactionToSignature(
        created: CrossmintTransactionResponse,
        abortSignal?: AbortSignal,
    ): Promise<SignatureBytes> {
        let response = created;
        let approvalSubmitted = false;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            abortSignal?.throwIfAborted();
            const pending = this.findPendingApprovalForSigner(response);
            if (
                response.status === 'awaiting-approval' &&
                this.signerSeed &&
                this.signer &&
                !approvalSubmitted &&
                pending !== undefined
            ) {
                response = await this.submitApproval(response, pending, abortSignal);
                approvalSubmitted = true;
                // Re-evaluate the new status immediately; approvalSubmitted
                // ensures the approval is signed and submitted at most once.
                continue;
            }
            const terminalSignature = this.resolveTerminalStatus(response, approvalSubmitted);
            if (terminalSignature) {
                return terminalSignature;
            }

            await abortableDelay(this.pollIntervalMs, abortSignal);
            response = await this.getTransaction(response.id, abortSignal);
        }

        const terminalSignature = this.resolveTerminalStatus(response, approvalSubmitted);
        if (terminalSignature) {
            return terminalSignature;
        }

        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Crossmint transaction polling timed out after ${this.maxPollAttempts} attempts`,
        });
    }

    private resolveTerminalStatus(
        response: CrossmintTransactionResponse,
        approvalSubmitted: boolean,
    ): SignatureBytes | undefined {
        const status = response.status as CrossmintTransactionStatus;
        switch (status) {
            case 'success':
                return this.extractSignature(response);
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
        abortSignal?: AbortSignal,
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
        const result = await this.request(
            path,
            'POST',
            {
                approvals: [{ signature: signatureB58, signer: this.signer }],
            },
            abortSignal,
        );
        return parseTransactionResponse(result, 'submit approval');
    }

    private async createTransaction(
        transaction: Transaction,
        abortSignal?: AbortSignal,
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
        const response = await this.request(
            path,
            'POST',
            body,
            abortSignal,
            await idempotencyKeyFromMessage(transaction.messageBytes),
        );
        return parseTransactionResponse(response, 'create transaction');
    }

    private async getTransaction(
        transactionId: string,
        abortSignal?: AbortSignal,
    ): Promise<CrossmintTransactionResponse> {
        const path = `/${API_VERSION}/wallets/${encodeURIComponent(this.walletLocator)}/transactions/${encodeURIComponent(transactionId)}`;
        const response = await this.request(path, 'GET', undefined, abortSignal);
        return parseTransactionResponse(response, 'get transaction');
    }

    private async request(
        path: string,
        method: 'GET' | 'POST',
        body?: unknown,
        abortSignal?: AbortSignal,
        idempotencyKey?: string,
    ): Promise<unknown> {
        const url = `${this.apiBaseUrl}${path}`;
        const headers: Record<string, string> = {
            'X-API-KEY': this.apiKey,
        };
        if (method === 'POST' && body != null) {
            headers['Content-Type'] = 'application/json';
        }
        if (idempotencyKey !== undefined) {
            headers['x-idempotency-key'] = idempotencyKey;
        }

        return await fetchSignerJson<unknown>({
            abortSignal,
            init: {
                body: body != null ? JSON.stringify(body) : undefined,
                headers,
                method,
            },
            providerName: 'Crossmint',
            url,
        });
    }

    private extractSignature(response: CrossmintTransactionResponse): SignatureBytes {
        let embeddedError: unknown;
        if (response.onChain?.transaction) {
            let executedTransaction: Transaction | undefined;
            try {
                base58Encoder ||= getBase58Encoder();
                executedTransaction = getTransactionDecoder().decode(
                    base58Encoder.encode(response.onChain.transaction),
                );
            } catch (error) {
                embeddedError = error;
            }
            if (executedTransaction) {
                const [, feePayerSignature] = Object.entries(executedTransaction.signatures)[0] ?? [];
                if (feePayerSignature) {
                    return feePayerSignature;
                }
                embeddedError = new Error('Crossmint transaction carries no fee-payer signature');
            }
        }

        const fromTxId = decodeSignatureString(response.onChain?.txId);
        if (fromTxId) {
            return fromTxId;
        }

        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            cause: embeddedError,
            message: 'Unable to extract signature from Crossmint transaction response',
        });
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
