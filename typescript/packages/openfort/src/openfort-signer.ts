import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    base64UrlDecoder,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
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
import type {
    MessagePartialSignerConfig,
    SignableMessage,
    SignatureDictionary,
    TransactionPartialSignerConfig,
} from '@solana/signers';
import { type Transaction, type TransactionWithinSizeLimit, type TransactionWithLifetime } from '@solana/transactions';

import type { AccountResponse, OpenfortSignerConfig, SignResponse } from './types.js';

/**
 * Create and initialize an Openfort backend wallet signer.
 *
 * Fetches the wallet's Solana address from `GET /v2/accounts/{accountId}`
 * during initialization and loads the wallet secret.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`, or `SIGNER_PARSING_ERROR`
 * when the address fetch fails.
 */
export async function createOpenfortSigner<TAddress extends string = string>(
    config: OpenfortSignerConfig,
): Promise<SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress>> {
    return await OpenfortSigner.create<TAddress>(config);
}

const DEFAULT_BASE_URL = 'https://api.openfort.io';
const ACCOUNTS_PATH = '/v2/accounts';
const BACKEND_PATH = '/v2/accounts/backend';
const JWT_LIFETIME_SECS = 120;

/**
 * Openfort backend wallet signer.
 *
 * Calls `POST /v2/accounts/backend/{accountId}/sign` for each signing request,
 * authenticated with `Authorization: Bearer <secret_key>` and an `x-wallet-auth`
 * ES256 JWT signed with the wallet secret. The Solana address is resolved
 * from `GET /v2/accounts/{accountId}` during `create()`.
 *
 * Use the static `create()` factory — it loads the P-256 wallet key and fetches
 * the address before returning.
 *
 * @example
 * ```typescript
 * const signer = await createOpenfortSigner({
 *   secretKey: process.env.OPENFORT_SECRET_KEY!,
 *   accountId: process.env.OPENFORT_ACCOUNT_ID!,
 *   walletSecret: process.env.OPENFORT_WALLET_SECRET!,
 * });
 * const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
 * ```
 */
class OpenfortSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;
    private readonly accountId: string;
    private readonly secretKey: string;
    private readonly walletKey: CryptoKey;
    private readonly baseUrl: string;
    private readonly apiHost: string;
    private readonly requestDelayMs: number;

    private constructor(config: {
        accountId: string;
        address: Address<TAddress>;
        apiHost: string;
        baseUrl: string;
        requestDelayMs: number;
        secretKey: string;
        walletKey: CryptoKey;
    }) {
        this.accountId = config.accountId;
        this.address = config.address;
        this.apiHost = config.apiHost;
        this.baseUrl = config.baseUrl;
        this.requestDelayMs = config.requestDelayMs;
        this.secretKey = config.secretKey;
        this.walletKey = config.walletKey;
    }

    /**
     * Create and initialize an OpenfortSigner.
     *
     * Loads the P-256 wallet key (base64 DER or PEM) and fetches the wallet's
     * Solana address from `GET /v2/accounts/{accountId}`.
     */
    static async create<TAddress extends string = string>(
        config: OpenfortSignerConfig,
    ): Promise<OpenfortSigner<TAddress>> {
        if (!config.secretKey) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required secretKey field',
            });
        }
        if (!config.accountId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required accountId field',
            });
        }
        if (!config.walletSecret) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required walletSecret field',
            });
        }

        const baseUrl = normalizeBaseUrl(config.baseUrl ?? DEFAULT_BASE_URL);
        const parsedBaseUrl = assertHttpsUrl(baseUrl, 'baseUrl');
        const apiHost = parsedBaseUrl.host;

        const requestDelayMs = config.requestDelayMs ?? 0;
        validateRequestDelayMs(requestDelayMs);

        const walletKey = await loadWalletKey(config.walletSecret);
        const address = await fetchAddress<TAddress>({
            accountId: config.accountId,
            baseUrl,
            secretKey: config.secretKey,
        });

        return new OpenfortSigner<TAddress>({
            accountId: config.accountId,
            address,
            apiHost,
            baseUrl,
            requestDelayMs,
            secretKey: config.secretKey,
            walletKey,
        });
    }

    /**
     * POST `/v2/accounts/backend/{accountId}/sign` with the message bytes
     * hex-encoded into the `data` field. For SVM accounts Openfort signs the
     * bytes as-is (no hashing) and returns a 64-byte ed25519 signature.
     */
    private async signBytes(message: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        const dataHex = `0x${getBase16Decoder().decode(message)}`;
        const path = `${BACKEND_PATH}/${encodeURIComponent(this.accountId)}/sign`;
        const url = `${this.baseUrl}${path}`;
        const body = { data: dataHex };

        const walletJwt = await createWalletJwt(this.walletKey, this.apiHost, 'POST', path, body);
        const headers = new Headers({
            Authorization: `Bearer ${this.secretKey}`,
            'Content-Type': 'application/json',
            'x-wallet-auth': walletJwt,
        });

        const data = await fetchSignerJson<SignResponse>({
            abortSignal,
            init: {
                body: JSON.stringify(body),
                headers,
                method: 'POST',
            },
            providerName: 'Openfort',
            url,
        });

        if (!data.signature) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Openfort response',
            });
        }

        const sigHex = data.signature.startsWith('0x') ? data.signature.slice(2) : data.signature;
        let signatureBytes: SignatureBytes;
        try {
            signatureBytes = getBase16Encoder().encode(sigHex) as SignatureBytes;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to hex-decode Openfort signature',
            });
        }

        if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${signatureBytes.length}`,
            });
        }

        return signatureBytes;
    }

    /** Sign multiple messages by POSTing the raw bytes to Openfort. */
    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signBytes(messageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: messageBytes,
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

    /** Sign multiple transactions by signing each transaction's `messageBytes`. */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const messageBytes = new Uint8Array(transaction.messageBytes);
                const signatureBytes = await this.signBytes(messageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: messageBytes,
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

    /** Returns true if `GET /v2/accounts/{accountId}` still resolves to the cached address. */
    async isAvailable(): Promise<boolean> {
        try {
            const address = await fetchAddress({
                accountId: this.accountId,
                baseUrl: this.baseUrl,
                secretKey: this.secretKey,
            });
            return address === this.address;
        } catch {
            return false;
        }
    }
}

function sortJson(value: unknown): unknown {
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) return (value as unknown[]).map(sortJson);
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
        sorted[key] = sortJson(obj[key]);
    }
    return sorted;
}

async function computeReqHash(body: unknown): Promise<string> {
    const json = JSON.stringify(sortJson(body));
    const data = new TextEncoder().encode(json);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
    return getBase16Decoder().decode(new Uint8Array(hashBuffer));
}

async function createWalletJwt(
    walletKey: CryptoKey,
    host: string,
    method: string,
    path: string,
    body: unknown,
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        exp: now + JWT_LIFETIME_SECS,
        iat: now,
        jti: globalThis.crypto.randomUUID(),
        nbf: now,
        reqHash: await computeReqHash(body),
        uris: [`${method} ${host}${path}`],
    };
    const header = { alg: 'ES256', typ: 'JWT' };

    const utf8Encoder = new TextEncoder();
    const headerB64 = base64UrlDecoder(utf8Encoder.encode(JSON.stringify(header)));
    const payloadB64 = base64UrlDecoder(utf8Encoder.encode(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const sigBuffer = await globalThis.crypto.subtle.sign(
        { hash: 'SHA-256', name: 'ECDSA' },
        walletKey,
        utf8Encoder.encode(signingInput),
    );
    return `${signingInput}.${base64UrlDecoder(new Uint8Array(sigBuffer))}`;
}

/**
 * Decode a P-256 PKCS#8 private key into a Web Crypto `CryptoKey`. Accepts
 * either a bare base64 DER body (the convenient single-line env-var form) or
 * a full PEM string (`-----BEGIN PRIVATE KEY-----` ... `-----END PRIVATE KEY-----`).
 * In both cases the headers and any whitespace are stripped before base64 decoding.
 */
async function loadWalletKey(walletSecret: string): Promise<CryptoKey> {
    try {
        const base64Body = walletSecret
            .replace(/-----BEGIN [^-]+-----/g, '')
            .replace(/-----END [^-]+-----/g, '')
            .replace(/\s+/g, '');
        const der = getBase64Encoder().encode(base64Body);
        return await globalThis.crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
            'sign',
        ]);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to load P-256 PKCS#8 key from walletSecret (expected PEM PKCS#8 ECDSA P-256 private key)',
        });
    }
}

async function fetchAddress<TAddress extends string = string>(config: {
    accountId: string;
    baseUrl: string;
    secretKey: string;
}): Promise<Address<TAddress>> {
    const url = `${config.baseUrl}${ACCOUNTS_PATH}/${encodeURIComponent(config.accountId)}`;

    const info = await fetchSignerJson<AccountResponse>({
        init: {
            headers: {
                Authorization: `Bearer ${config.secretKey}`,
            },
            method: 'GET',
        },
        providerName: 'Openfort',
        url,
    });

    if (!info.address) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: 'Missing address in Openfort getAccount response',
        });
    }

    try {
        assertIsAddress(info.address);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: `Openfort returned non-Solana address for ${config.accountId}: ensure the account is on an SVM chain`,
        });
    }
    return info.address as Address<TAddress>;
}
