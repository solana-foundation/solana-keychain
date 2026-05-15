import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';

export type PrivyAuthorizationSignFn = (payload: Uint8Array) => Promise<string> | string;

export interface PrivyAuthorizationContext {
    /**
     * Base64-encoded PKCS8 P-256 private keys exported by Privy.
     * `wallet-auth:` and `wallet-api:` prefixes are accepted.
     */
    authorization_private_keys?: readonly string[];
    /** External signers that receive the exact canonical payload bytes. */
    sign_fns?: readonly PrivyAuthorizationSignFn[];
    /**
     * Precomputed base64 authorization signatures for this exact request.
     * Prefer `sign_fns` for reusable signer configs.
     */
    signatures?: readonly string[];
}

export interface PrivyAuthorizationRequestInput {
    body: unknown;
    headers: {
        'privy-app-id': string;
        'privy-idempotency-key'?: string;
        'privy-request-expiry'?: string;
    };
    method: 'DELETE' | 'PATCH' | 'POST' | 'PUT';
    url: string;
    version: 1;
}

export type PrivyAuthorizationContextProvider = (
    request: PrivyAuthorizationRequestInput,
) => PrivyAuthorizationContext | Promise<PrivyAuthorizationContext | undefined> | undefined;

export type PrivyAuthorizationConfig = PrivyAuthorizationContext | PrivyAuthorizationContextProvider;

interface PreparePrivyAuthorizationHeadersInput {
    appId: string;
    authorizationContext: PrivyAuthorizationConfig | undefined;
    body: unknown;
    method: PrivyAuthorizationRequestInput['method'];
    requestExpiryMs: number | null;
    url: string;
}

export interface PrivyAuthorizationHeaders {
    'privy-authorization-signature'?: string;
    'privy-request-expiry'?: string;
}

const DEFAULT_PRIVY_AUTHORIZATION_REQUEST_EXPIRY_MS = 15 * 60 * 1000;

export function getDefaultPrivyAuthorizationRequestExpiryMs(): number {
    return DEFAULT_PRIVY_AUTHORIZATION_REQUEST_EXPIRY_MS;
}

export async function preparePrivyAuthorizationHeaders({
    appId,
    authorizationContext,
    body,
    method,
    requestExpiryMs,
    url,
}: PreparePrivyAuthorizationHeadersInput): Promise<PrivyAuthorizationHeaders> {
    if (!authorizationContext) {
        return {};
    }

    const requestExpiry =
        requestExpiryMs === null
            ? undefined
            : String(Date.now() + (requestExpiryMs ?? DEFAULT_PRIVY_AUTHORIZATION_REQUEST_EXPIRY_MS));

    const request: PrivyAuthorizationRequestInput = {
        body,
        headers: {
            'privy-app-id': appId,
            ...(requestExpiry ? { 'privy-request-expiry': requestExpiry } : {}),
        },
        method,
        url,
        version: 1,
    };

    const context =
        typeof authorizationContext === 'function' ? await authorizationContext(request) : authorizationContext;

    if (!context) {
        return {};
    }

    const signatures = await generatePrivyAuthorizationSignatures(request, context);
    if (signatures.length === 0) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'authorizationContext must include authorization_private_keys, signatures, or sign_fns',
        });
    }

    return {
        'privy-authorization-signature': signatures.join(','),
        ...(requestExpiry ? { 'privy-request-expiry': requestExpiry } : {}),
    };
}

export async function generatePrivyAuthorizationSignatures(
    request: PrivyAuthorizationRequestInput,
    authorizationContext: PrivyAuthorizationContext,
): Promise<string[]> {
    const payload = formatPrivyAuthorizationSignaturePayload(request);
    const providedSignatures = [...(authorizationContext.signatures ?? [])];
    const privateKeySignatures = await Promise.all(
        (authorizationContext.authorization_private_keys ?? []).map(privateKey =>
            generatePrivyAuthorizationSignature(privateKey, payload),
        ),
    );
    const signFnSignatures = await Promise.all(
        (authorizationContext.sign_fns ?? []).map(signFn => Promise.resolve(signFn(payload))),
    );

    return [...providedSignatures, ...privateKeySignatures, ...signFnSignatures];
}

export function formatPrivyAuthorizationSignaturePayload(request: PrivyAuthorizationRequestInput): Uint8Array {
    const body = isRecord(request.body) && Object.keys(request.body).length === 0 ? '' : request.body;
    const serializedInput = canonicalizeJson({
        ...request,
        body,
    });

    if (!serializedInput) {
        throwSignerError(SignerErrorCode.SERIALIZATION_ERROR, {
            message: 'Failed to serialize Privy authorization request',
        });
    }

    return new TextEncoder().encode(serializedInput);
}

async function generatePrivyAuthorizationSignature(
    authorizationPrivateKey: string,
    payload: Uint8Array,
): Promise<string> {
    const nodeCrypto = await importNodeCryptoForAuthorizationPrivateKeys();

    try {
        const privateKey = parseP256PrivateKey(nodeCrypto, authorizationPrivateKey);
        const signature = nodeCrypto.sign('sha256', payload, {
            dsaEncoding: 'der',
            key: privateKey,
        });
        return Buffer.from(signature).toString('base64');
    } catch (error) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            cause: error,
            message: 'Failed to create Privy authorization signature',
        });
    }
}

async function importNodeCryptoForAuthorizationPrivateKeys(): Promise<typeof import('node:crypto')> {
    try {
        return await import('node:crypto');
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'authorization_private_keys requires Node.js crypto support; use sign_fns instead',
        });
    }
}

function parseP256PrivateKey(
    nodeCrypto: typeof import('node:crypto'),
    authorizationPrivateKey: string,
): import('node:crypto').KeyObject {
    const unprefixed = authorizationPrivateKey.replace(/^wallet-auth:/, '').replace(/^wallet-api:/, '');
    const normalized = unprefixed.replace(/\s+/g, '');

    if (unprefixed.includes('-----BEGIN')) {
        return nodeCrypto.createPrivateKey(unprefixed.replace(/\\n/g, '\n').trim());
    }

    return nodeCrypto.createPrivateKey({
        format: 'der',
        key: Buffer.from(normalized, 'base64'),
        type: 'pkcs8',
    });
}

function canonicalizeJson(value: unknown): string | undefined {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') {
        return JSON.stringify(value);
    }

    if (typeof value === 'number') {
        return Number.isFinite(value) ? JSON.stringify(value) : undefined;
    }

    if (Array.isArray(value)) {
        const items: string[] = [];
        for (const item of value) {
            const serializedItem = canonicalizeJson(item);
            if (serializedItem === undefined) {
                return undefined;
            }
            items.push(serializedItem);
        }
        return `[${items.join(',')}]`;
    }

    if (isRecord(value)) {
        const entries = Object.entries(value)
            .filter(([, entryValue]) => entryValue !== undefined)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
        const serializedEntries = entries.map(([key, entryValue]) => {
            const serializedValue = canonicalizeJson(entryValue);
            if (serializedValue === undefined) {
                return undefined;
            }
            return `${JSON.stringify(key)}:${serializedValue}`;
        });

        if (serializedEntries.some(entry => entry === undefined)) {
            return undefined;
        }

        return `{${serializedEntries.join(',')}}`;
    }

    return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
