import { type Address, assertIsAddress } from '@solana/addresses';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignerError,
    extractSignatureFromWireTransaction,
    fetchSignerJson,
    normalizeBaseUrl,
    normalizePrivateKeyPem,
    signBatchStaggered,
    SignerErrorCode,
    type SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import type { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    type Base64EncodedWireTransaction,
    getBase64EncodedWireTransaction,
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

const DEFAULT_API_BASE_URL = 'https://api.utila.io';
const UTILA_API_AUDIENCE = 'https://api.utila.io/';
const DEFAULT_POLL_INTERVAL_MS = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS = 60;
const TOKEN_TTL_MINUTES = 55;
const TOKEN_TTL = `${TOKEN_TTL_MINUTES}m`;
const TOKEN_TTL_MS = TOKEN_TTL_MINUTES * 60 * 1000;
/** Re-mint the cached access token when it is within this window of expiry. */
const TOKEN_REFRESH_MARGIN_MS = 60_000;

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
    private readonly requestDelayMs: number;
    private readonly serviceAccountEmail: string;
    private readonly serviceAccountPrivateKey: ImportedPrivateKey;
    private readonly vaultId: string;
    private readonly walletId: string;
    private accessToken: { expiresAtMs: number; tokenPromise: Promise<string> } | null = null;

    static async create<TAddress extends string = string>(config: UtilaSignerConfig): Promise<UtilaSigner<TAddress>> {
        validateRequired('serviceAccountEmail', config.serviceAccountEmail);
        validateRequired('serviceAccountPrivateKeyPem', config.serviceAccountPrivateKeyPem);
        validateRequired('vaultId', config.vaultId);
        validateRequired('walletId', config.walletId);
        validateRequired('network', config.network);

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_API_BASE_URL);
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

        const requestDelayMs = config.requestDelayMs ?? 0;
        validateRequestDelayMs(requestDelayMs);

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
            requestDelayMs,
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
        requestDelayMs: number;
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
        this.requestDelayMs = config.requestDelayMs;
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
        return await signBatchStaggered(
            transactions,
            transaction => this.signTransactionWithUtila(transaction),
            this.requestDelayMs,
        );
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

        const sigDict = extractSignatureFromWireTransaction({
            base64WireTransaction: rawSignedTransaction as Base64EncodedWireTransaction,
            signerAddress: this.address,
        });
        await assertSignatureValid({
            data: transaction.messageBytes,
            signature: sigDict[this.address],
            signerAddress: this.address,
        });
        return sigDict;
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

    /**
     * Return a valid service-account access token, minting a new one only when
     * there is no cached token or the cached token is within
     * {@link TOKEN_REFRESH_MARGIN_MS} of expiry. The pending mint promise is
     * cached (not the resolved token) so concurrent callers share one mint;
     * a failed mint evicts itself so the next call retries.
     */
    private getAccessToken(): Promise<string> {
        if (!this.accessToken || Date.now() >= this.accessToken.expiresAtMs - TOKEN_REFRESH_MARGIN_MS) {
            const entry = {
                expiresAtMs: Date.now() + TOKEN_TTL_MS,
                tokenPromise: createUtilaAccessToken(this.serviceAccountEmail, this.serviceAccountPrivateKey),
            };
            this.accessToken = entry;
            entry.tokenPromise.catch(() => {
                if (this.accessToken === entry) {
                    this.accessToken = null;
                }
            });
        }
        return this.accessToken.tokenPromise;
    }

    private async request<T>(path: string, method: 'GET' | 'POST', body?: unknown): Promise<T> {
        const url = `${this.apiBaseUrl}${path}`;
        const token = await this.getAccessToken();
        const headers: Record<string, string> = {
            Authorization: `Bearer ${token}`,
        };
        if (body != null) {
            headers['Content-Type'] = 'application/json';
        }

        return await fetchSignerJson<T>({
            init: {
                body: body != null ? JSON.stringify(body) : undefined,
                headers,
                method,
            },
            providerName: 'Utila',
            url,
        });
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

    return await fetchSignerJson<UtilaWalletResponse>({
        init: {
            headers: {
                Authorization: `Bearer ${token}`,
            },
            method: 'GET',
        },
        providerName: 'Utila',
        url,
    });
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

function trimResourcePrefix(value: string, prefix: string): string {
    return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

function trimWalletId(value: string): string {
    const marker = '/wallets/';
    const markerIndex = value.lastIndexOf(marker);
    return markerIndex === -1 ? value : value.slice(markerIndex + marker.length);
}
