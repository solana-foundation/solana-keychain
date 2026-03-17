import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase58Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    base64UrlDecoder,
    createSignatureDictionary,
    extractSignatureFromWireTransaction,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { createKeyPairFromBytes, SignatureBytes } from '@solana/keys';
import type { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    type Base64EncodedWireTransaction,
    getBase64EncodedWireTransaction,
    type Transaction,
    type TransactionWithinSizeLimit,
    type TransactionWithLifetime,
} from '@solana/transactions';

import type { CdpSignerConfig, SignMessageResponse, SignTransactionResponse } from './types.js';

/**
 * Create and initialize a CDP-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export async function createCdpSigner<TAddress extends string = string>(
    config: CdpSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await CdpSigner.create(config);
}

// --- Module-level constants ---

const CDP_DEFAULT_BASE_URL = 'https://api.cdp.coinbase.com';
const CDP_BASE_PATH = '/platform/v2/solana/accounts';

let base16Decoder: ReturnType<typeof getBase16Decoder> | undefined;
let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let utf8Decoder: TextDecoder | undefined;
let utf8Encoder: TextEncoder | undefined;

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
    base16Decoder ||= getBase16Decoder();
    const json = JSON.stringify(sortJson(body));
    utf8Encoder ||= new TextEncoder();
    const data = utf8Encoder.encode(json);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
    return base16Decoder.decode(new Uint8Array(hashBuffer));
}

async function signJwt(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    privateKey: CryptoKey,
    algorithm: 'EdDSA' | 'ES256',
): Promise<string> {
    utf8Encoder ||= new TextEncoder();
    const headerB64 = base64UrlDecoder(utf8Encoder.encode(JSON.stringify(header)));
    const payloadB64 = base64UrlDecoder(utf8Encoder.encode(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const inputBytes = utf8Encoder.encode(signingInput);

    let sigBuffer: ArrayBuffer;
    if (algorithm === 'EdDSA') {
        sigBuffer = await globalThis.crypto.subtle.sign('Ed25519', privateKey, inputBytes);
    } else {
        // ES256: ECDSA with P-256 + SHA-256; Web Crypto returns IEEE P1363 (r||s) format
        sigBuffer = await globalThis.crypto.subtle.sign({ hash: 'SHA-256', name: 'ECDSA' }, privateKey, inputBytes);
    }

    return `${signingInput}.${base64UrlDecoder(new Uint8Array(sigBuffer))}`;
}

async function createAuthJwt(
    apiKeyId: string,
    apiKey: CryptoKey,
    host: string,
    method: string,
    path: string,
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = {
        alg: 'EdDSA',
        kid: apiKeyId,
        nonce: globalThis.crypto.randomUUID().replace(/-/g, ''),
        typ: 'JWT',
    };
    const payload = {
        exp: now + 120,
        iat: now,
        iss: 'cdp',
        nbf: now,
        sub: apiKeyId,
        uris: [`${method} ${host}${path}`],
    };
    return await signJwt(header, payload, apiKey, 'EdDSA');
}

async function createWalletJwt(
    walletKey: CryptoKey,
    host: string,
    method: string,
    path: string,
    body?: unknown,
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        exp: now + 120,
        iat: now,
        jti: globalThis.crypto.randomUUID(),
        nbf: now,
        uris: [`${method} ${host}${path}`],
    };
    if (shouldIncludeReqHash(body)) {
        payload['reqHash'] = await computeReqHash(body);
    }
    const header = { alg: 'ES256', typ: 'JWT' };
    return await signJwt(header, payload, walletKey, 'ES256');
}

// --- Key loading ---

/**
 * Load the Ed25519 CDP API key from a base64-encoded 64-byte secret (seed || pubkey).
 *
 * Uses `createKeyPairFromBytes` from `@solana/keys`, which validates that the
 * public key bytes match the seed — equivalent to the Rust `validate_ed25519_keypair_bytes`
 * check. This also ensures all crypto uses the Web Crypto API for cross-runtime support.
 */
async function loadApiKey(cdpApiKeySecret: string): Promise<CryptoKey> {
    let keyPair: CryptoKeyPair;
    try {
        base64Encoder ||= getBase64Encoder();
        const bytes = base64Encoder.encode(cdpApiKeySecret);
        // createKeyPairFromBytes validates:
        //   - input is exactly 64 bytes (seed || pubkey)
        //   - the public key bytes match the seed (signs test data and verifies)
        keyPair = await createKeyPairFromBytes(bytes);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message:
                'Invalid cdpApiKeySecret: must be a base64-encoded 64-byte Ed25519 key (seed || pubkey) where the public key matches the seed',
        });
    }
    return keyPair.privateKey;
}

async function loadWalletKey(walletSecret: string): Promise<CryptoKey> {
    try {
        base64Encoder ||= getBase64Encoder();
        const der = base64Encoder.encode(walletSecret);
        return await globalThis.crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
            'sign',
        ]);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to load P-256 PKCS#8 key from cdpWalletSecret',
        });
    }
}

/**
 * CDP-based Solana signer using Coinbase Developer Platform's managed key infrastructure.
 *
 * Makes direct HTTP calls to the CDP REST API — no vendor SDK required.
 * Authentication uses two JWTs per signing request:
 * - `Authorization: Bearer <jwt>` — signed with the CDP API private key (Ed25519)
 * - `X-Wallet-Auth: <jwt>` — signed with the wallet secret (always ES256)
 *
 * The CDP account address must be provided at construction time.
 * Use CDP's API or dashboard to create a Solana account first.
 *
 * Use the static `create()` factory to construct an instance — it validates the
 * Ed25519 key pair (seed↔pubkey match) and loads both keys asynchronously.
 *
 * @example
 * ```typescript
 * const signer = await CdpSigner.create({
 *   cdpApiKeyId: process.env.CDP_API_KEY_ID!,
 *   cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
 *   cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
 *   address: process.env.CDP_SOLANA_ADDRESS!,
 * });
 * const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
 * ```
 *
 * @deprecated Prefer `createCdpSigner()`. Class export will be removed in a future version.
 */
export class CdpSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiKeyId: string;
    private readonly apiKey: CryptoKey;
    private readonly walletKey: CryptoKey;
    private readonly apiHost: string;
    private readonly baseUrl: string;
    private readonly requestDelayMs: number;

    private constructor(config: {
        address: Address<TAddress>;
        apiHost: string;
        apiKey: CryptoKey;
        apiKeyId: string;
        baseUrl: string;
        requestDelayMs: number;
        walletKey: CryptoKey;
    }) {
        this.address = config.address;
        this.apiKeyId = config.apiKeyId;
        this.apiKey = config.apiKey;
        this.walletKey = config.walletKey;
        this.baseUrl = config.baseUrl;
        this.apiHost = config.apiHost;
        this.requestDelayMs = config.requestDelayMs;
    }

    /**
     * Create and initialize a CdpSigner.
     *
     * Validates the Ed25519 API key (seed↔pubkey match via `createKeyPairFromBytes`)
     * and loads the P-256 wallet key. Both keys are loaded in parallel.
     * @deprecated Use `createCdpSigner()` instead.
     */
    static async create<TAddress extends string = string>(config: CdpSignerConfig): Promise<CdpSigner<TAddress>> {
        if (!config.cdpApiKeyId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required cdpApiKeyId field',
            });
        }

        if (!config.cdpApiKeySecret) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required cdpApiKeySecret field',
            });
        }

        if (!config.cdpWalletSecret) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required cdpWalletSecret field',
            });
        }

        if (!config.address) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required address field',
            });
        }

        let address: Address<TAddress>;
        try {
            assertIsAddress(config.address);
            address = config.address as Address<TAddress>;
        } catch (error) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana address format',
            });
        }

        const baseUrl = normalizeBaseUrl(config.baseUrl ?? CDP_DEFAULT_BASE_URL);
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

        const [apiKey, walletKey] = await Promise.all([
            loadApiKey(config.cdpApiKeySecret),
            loadWalletKey(config.cdpWalletSecret),
        ]);

        return new CdpSigner<TAddress>({
            address,
            apiHost,
            apiKey,
            apiKeyId: config.cdpApiKeyId,
            baseUrl,
            requestDelayMs,
            walletKey,
        });
    }

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    private decodeMessageBytes(messageBytes: Uint8Array): string {
        try {
            utf8Decoder ||= new TextDecoder('utf-8', { fatal: true });
            return utf8Decoder.decode(messageBytes);
        } catch (error) {
            throwSignerError(SignerErrorCode.SERIALIZATION_ERROR, {
                cause: error,
                message: 'CDP signMessage requires a valid UTF-8 message',
            });
        }
    }

    private async buildPostHeaders(path: string, body: unknown): Promise<Headers> {
        const [authJwt, walletJwt] = await Promise.all([
            createAuthJwt(this.apiKeyId, this.apiKey, this.apiHost, 'POST', path),
            createWalletJwt(this.walletKey, this.apiHost, 'POST', path, body),
        ]);
        return new Headers({
            Authorization: `Bearer ${authJwt}`,
            'Content-Type': 'application/json',
            'X-Wallet-Auth': walletJwt,
        });
    }

    private async buildGetHeaders(path: string): Promise<Headers> {
        const authJwt = await createAuthJwt(this.apiKeyId, this.apiKey, this.apiHost, 'GET', path);
        return new Headers({
            Authorization: `Bearer ${authJwt}`,
        });
    }

    /**
     * Sign a UTF-8 message string using the CDP API.
     * @returns The 64-byte Ed25519 signature.
     */
    private async callSignMessage(message: string): Promise<SignatureBytes> {
        const path = `${CDP_BASE_PATH}/${this.address}/sign/message`;
        const url = `${this.baseUrl}${path}`;
        const body = { message };
        const headers = await this.buildPostHeaders(path, body);

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
                message: 'CDP signMessage network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `CDP signMessage API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let data: SignMessageResponse;
        try {
            data = (await response.json()) as SignMessageResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse CDP signMessage response',
            });
        }

        // CDP returns a base58-encoded Ed25519 signature
        base58Encoder ||= getBase58Encoder();
        const signatureBytes = base58Encoder.encode(data.signature) as SignatureBytes;

        if (signatureBytes.length !== 64) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature length: expected 64 bytes, got ${signatureBytes.length}`,
            });
        }

        return signatureBytes;
    }

    /**
     * Sign a base64-encoded wire transaction using the CDP API.
     * @returns The fully-signed wire transaction (base64-encoded).
     */
    private async callSignTransaction(
        wireTransaction: Base64EncodedWireTransaction,
    ): Promise<Base64EncodedWireTransaction> {
        const path = `${CDP_BASE_PATH}/${this.address}/sign/transaction`;
        const url = `${this.baseUrl}${path}`;
        const body = { transaction: wireTransaction };
        const headers = await this.buildPostHeaders(path, body);

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
                message: 'CDP signTransaction network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `CDP signTransaction API error: ${response.status}`,
                response: sanitizeRemoteErrorResponse(errorText),
                status: response.status,
            });
        }

        let data: SignTransactionResponse;
        try {
            data = (await response.json()) as SignTransactionResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse CDP signTransaction response',
            });
        }

        return data.signedTransaction as Base64EncodedWireTransaction;
    }

    /**
     * Sign multiple messages using the CDP API.
     * Message bytes are decoded as UTF-8 before sending to the CDP signMessage endpoint.
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const utf8Message = this.decodeMessageBytes(message.content);
                const signatureBytes = await this.callSignMessage(utf8Message);
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
     * Sign multiple transactions using the CDP API.
     * Returns the signature extracted from the fully-signed wire transaction.
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const wireTransaction = getBase64EncodedWireTransaction(transaction);
                const signedWireTx = await this.callSignTransaction(wireTransaction);
                const sigDict = extractSignatureFromWireTransaction({
                    base64WireTransaction: signedWireTx,
                    signerAddress: this.address,
                });
                const signatureBytes = Object.values(sigDict)[0];
                if (!signatureBytes) {
                    throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        address: this.address,
                        message: 'No signature bytes found in extracted signature dictionary',
                    });
                }
                await assertSignatureValid({
                    data: transaction.messageBytes,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return sigDict;
            }),
        );
    }

    /**
     * Check if the CDP API is reachable and this specific account is accessible.
     */
    async isAvailable(): Promise<boolean> {
        try {
            const path = `${CDP_BASE_PATH}/${this.address}`;
            const headers = await this.buildGetHeaders(path);
            const response = await fetch(`${this.baseUrl}${path}`, {
                headers,
                method: 'GET',
            });
            return response.ok;
        } catch {
            return false;
        }
    }
}

function normalizeBaseUrl(baseUrl: string): string {
    let normalized = baseUrl.trim();
    if (normalized.endsWith('/platform')) {
        normalized = normalized.slice(0, -'/platform'.length);
    } else if (normalized.endsWith('/platform/')) {
        normalized = normalized.slice(0, -'/platform/'.length);
    }
    if (normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
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

function shouldIncludeReqHash(body: unknown): boolean {
    if (body === undefined || body === null) {
        return false;
    }
    if (typeof body !== 'object') {
        return true;
    }
    if (Array.isArray(body)) {
        return body.length > 0;
    }
    const entries = Object.entries(body as Record<string, unknown>);
    if (entries.length === 0) {
        return false;
    }
    return entries.some(([, value]) => value !== undefined);
}
