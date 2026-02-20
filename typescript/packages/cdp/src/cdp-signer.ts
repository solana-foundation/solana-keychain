import * as crypto from 'node:crypto';

import { Address, assertIsAddress } from '@solana/addresses';
import { getBase58Encoder } from '@solana/codecs-strings';
import {
    createSignatureDictionary,
    extractSignatureFromWireTransaction,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import type { SignatureBytes } from '@solana/keys';
import type { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    type Base64EncodedWireTransaction,
    getBase64EncodedWireTransaction,
    type Transaction,
    type TransactionWithinSizeLimit,
    type TransactionWithLifetime,
} from '@solana/transactions';

import type { CdpSignerConfig, SignMessageResponse, SignTransactionResponse } from './types.js';

// --- Module-level constants ---

const CDP_DEFAULT_BASE_URL = 'https://api.cdp.coinbase.com';
const CDP_BASE_PATH = '/platform/v2/solana/accounts';

// PKCS#8 DER header prefix for Ed25519 private keys (RFC 8410).
// Structure: SEQUENCE { version INTEGER 0, SEQUENCE { OID id-EdDSA }, OCTET STRING { OCTET STRING { seed } } }
const ED25519_PKCS8_PREFIX = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// Cache codec instances at module level — avoids repeated allocation in hot path.
// Note: in @solana/codecs-strings the naming is from the wire-format perspective:
//   getBase58Encoder().encode(string)     → Uint8Array     (base58 → bytes)
const base58Encoder = getBase58Encoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

// --- JWT helpers ---

function base64urlEncode(data: string): string {
    return Buffer.from(data).toString('base64url');
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

function computeReqHash(body: unknown): string {
    const json = JSON.stringify(sortJson(body));
    return crypto.createHash('sha256').update(json).digest('hex');
}

function signJwt(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    privateKey: crypto.KeyObject,
    algorithm: 'EdDSA' | 'ES256',
): string {
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const inputBuffer = Buffer.from(signingInput);

    let sigBytes: Buffer;
    if (algorithm === 'EdDSA') {
        sigBytes = crypto.sign(null, inputBuffer, privateKey);
    } else {
        // ES256: P-256 + SHA-256 with IEEE P1363 encoding → raw 64-byte r||s (no DER wrapping)
        sigBytes = crypto.sign('sha256', inputBuffer, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    }

    return `${signingInput}.${sigBytes.toString('base64url')}`;
}

function createAuthJwt(
    apiKeyId: string,
    apiKey: crypto.KeyObject,
    host: string,
    method: string,
    path: string,
): string {
    const now = Math.floor(Date.now() / 1000);
    const header = {
        alg: 'EdDSA',
        kid: apiKeyId,
        typ: 'JWT',
        nonce: crypto.randomUUID().replace(/-/g, ''), // simple() equivalent from Rust
    };
    const payload = {
        sub: apiKeyId,
        iss: 'cdp',
        iat: now,
        nbf: now,
        exp: now + 120,
        uris: [`${method} ${host}${path}`],
    };
    return signJwt(header, payload, apiKey, 'EdDSA');
}

function createWalletJwt(
    walletKey: crypto.KeyObject,
    host: string,
    method: string,
    path: string,
    body?: unknown,
): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        uris: [`${method} ${host}${path}`],
        iat: now,
        nbf: now,
        exp: now + 120,
        jti: crypto.randomUUID(),
    };
    if (shouldIncludeReqHash(body)) {
        payload['reqHash'] = computeReqHash(body);
    }
    const header = { alg: 'ES256', typ: 'JWT' };
    return signJwt(header, payload, walletKey, 'ES256');
}

// --- Key loading ---

function loadApiKey(cdpApiKeySecret: string): crypto.KeyObject {
    // Base64-encoded Ed25519 key: 64 bytes (seed || pubkey)
    const bytes = Buffer.from(cdpApiKeySecret, 'base64');
    if (bytes.length !== 64) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Ed25519 cdpApiKeySecret must be 64 bytes when base64-decoded (seed || pubkey), got ${bytes.length}`,
        });
    }

    const seed = bytes.subarray(0, 32);
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);

    let key: crypto.KeyObject;
    try {
        key = crypto.createPrivateKey({ format: 'der', type: 'pkcs8', key: pkcs8Der });
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to load Ed25519 private key from cdpApiKeySecret',
        });
    }
    return key;
}

function loadWalletKey(walletSecret: string): crypto.KeyObject {
    const der = Buffer.from(walletSecret, 'base64');
    let key: crypto.KeyObject;
    try {
        key = crypto.createPrivateKey({ format: 'der', type: 'pkcs8', key: der });
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to load P-256 PKCS#8 key from cdpWalletSecret',
        });
    }
    return key;
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
 * @example
 * ```typescript
 * const signer = new CdpSigner({
 *   cdpApiKeyId: process.env.CDP_API_KEY_ID!,
 *   cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
 *   cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
 *   address: process.env.CDP_SOLANA_ADDRESS!,
 * });
 * const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
 * ```
 */
export class CdpSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiKeyId: string;
    private readonly apiKey: crypto.KeyObject;
    private readonly walletKey: crypto.KeyObject;
    private readonly apiHost: string;
    private readonly baseUrl: string;
    private readonly requestDelayMs: number;

    constructor(config: CdpSignerConfig) {
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

        try {
            assertIsAddress(config.address);
            this.address = config.address as Address<TAddress>;
        } catch (error) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana address format',
            });
        }

        this.apiKey = loadApiKey(config.cdpApiKeySecret);
        this.walletKey = loadWalletKey(config.cdpWalletSecret);

        this.baseUrl = normalizeBaseUrl(config.baseUrl ?? CDP_DEFAULT_BASE_URL);
        try {
            this.apiHost = new URL(this.baseUrl).host;
        } catch (error) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: `Invalid baseUrl: ${this.baseUrl}`,
            });
        }

        this.apiKeyId = config.cdpApiKeyId;
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.validateRequestDelayMs(this.requestDelayMs);
    }

    private validateRequestDelayMs(requestDelayMs: number): void {
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

    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    private decodeMessageBytes(messageBytes: Uint8Array): string {
        try {
            return utf8Decoder.decode(messageBytes);
        } catch (error) {
            throwSignerError(SignerErrorCode.SERIALIZATION_ERROR, {
                cause: error,
                message: 'CDP signMessage requires a valid UTF-8 message',
            });
        }
    }

    private buildPostHeaders(path: string, body: unknown): Headers {
        const authJwt = createAuthJwt(this.apiKeyId, this.apiKey, this.apiHost, 'POST', path);
        const walletJwt = createWalletJwt(this.walletKey, this.apiHost, 'POST', path, body);
        return new Headers({
            Authorization: `Bearer ${authJwt}`,
            'X-Wallet-Auth': walletJwt,
            'Content-Type': 'application/json',
        });
    }

    private buildGetHeaders(path: string): Headers {
        const authJwt = createAuthJwt(this.apiKeyId, this.apiKey, this.apiHost, 'GET', path);
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
        const headers = this.buildPostHeaders(path, body);

        let response: Response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
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
                response: errorText,
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
        const headers = this.buildPostHeaders(path, body);

        let response: Response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
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
                response: errorText,
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
                return extractSignatureFromWireTransaction({
                    base64WireTransaction: signedWireTx,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Check if the CDP API is reachable and this specific account is accessible.
     */
    async isAvailable(): Promise<boolean> {
        const path = `${CDP_BASE_PATH}/${this.address}`;
        const headers = this.buildGetHeaders(path);

        let response: Response;
        try {
            response = await fetch(`${this.baseUrl}${path}`, {
                method: 'GET',
                headers,
            });
        } catch {
            return false;
        }

        return response.ok;
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
