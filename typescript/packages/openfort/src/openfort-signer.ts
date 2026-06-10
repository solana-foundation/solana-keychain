import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    base64UrlDecoder,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import type { SignableMessage, SignatureDictionary } from '@solana/signers';
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
): Promise<SolanaSigner<TAddress>> {
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
 * const signer = await OpenfortSigner.create({
 *   secretKey: process.env.OPENFORT_SECRET_KEY!,
 *   accountId: process.env.OPENFORT_ACCOUNT_ID!,
 *   walletSecret: process.env.OPENFORT_WALLET_SECRET!,
 * });
 * const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
 * ```
 *
 * @deprecated Prefer `createOpenfortSigner()`. Class export will be removed in a future version.
 */
export class OpenfortSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
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
     *
     * @deprecated Use `createOpenfortSigner()` instead.
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

        const baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
        const parsedBaseUrl = parseAndValidateHttpsBaseUrl(baseUrl);
        const apiHost = parsedBaseUrl.host;

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

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * POST `/v2/accounts/backend/{accountId}/sign` with the message bytes
     * hex-encoded into the `data` field. For SVM accounts Openfort signs the
     * bytes as-is (no hashing) and returns a 64-byte ed25519 signature.
     */
    private async signBytes(message: Uint8Array): Promise<SignatureBytes> {
        const dataHex = `0x${getBase16Decoder().decode(message)}`;
        const path = `${BACKEND_PATH}/${this.accountId}/sign`;
        const url = `${this.baseUrl}${path}`;
        const body = { data: dataHex };

        const walletJwt = await createWalletJwt(this.walletKey, this.apiHost, 'POST', path, body);
        const headers = new Headers({
            Authorization: `Bearer ${this.secretKey}`,
            'Content-Type': 'application/json',
            'x-wallet-auth': walletJwt,
        });

        let response: Response;
        try {
            response = await fetch(url, {
                body: JSON.stringify(body),
                headers,
                method: 'POST',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Openfort sign network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Openfort sign API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let data: SignResponse;
        try {
            data = (await response.json()) as SignResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Openfort sign response',
            });
        }

        if (!data.signature) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Openfort response',
            });
        }

        // Hex-decode signature (`0x` prefix optional).
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
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signBytes(messageBytes);
                await assertSignatureValid({
                    data: messageBytes,
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

    /** Sign multiple transactions by signing each transaction's `messageBytes`. */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const messageBytes = new Uint8Array(transaction.messageBytes);
                const signatureBytes = await this.signBytes(messageBytes);
                await assertSignatureValid({
                    data: messageBytes,
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

// --- JWT construction (ES256, signed with the wallet secret) ---

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

// --- Key + URL helpers ---

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

function parseAndValidateHttpsBaseUrl(baseUrl: string): URL {
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(baseUrl);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'baseUrl is not a valid URL',
        });
    }

    if (parsedUrl.protocol !== 'https:') {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'baseUrl must use HTTPS',
        });
    }

    return parsedUrl;
}

async function fetchAddress<TAddress extends string = string>(config: {
    accountId: string;
    baseUrl: string;
    secretKey: string;
}): Promise<Address<TAddress>> {
    const url = `${config.baseUrl}${ACCOUNTS_PATH}/${config.accountId}`;

    let response: Response;
    try {
        response = await fetch(url, {
            headers: {
                Authorization: `Bearer ${config.secretKey}`,
            },
            method: 'GET',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Openfort getAccount network request failed',
            url,
        });
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Openfort getAccount API error: ${response.status}`,
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    let info: AccountResponse;
    try {
        info = (await response.json()) as AccountResponse;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Openfort getAccount response',
        });
    }

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
