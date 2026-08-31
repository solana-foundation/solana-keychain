import { getBase16Decoder } from '@solana/codecs-strings';
import { normalizePrivateKeyPem, SignerErrorCode, throwSignerError } from '@solana/keychain-core';
import { importPKCS8, SignJWT } from 'jose';

let base16Decoder: ReturnType<typeof getBase16Decoder> | undefined;
const JWT_TTL_SECS = 120;
const JWT_SKEW_LEEWAY_SECS = 60;

/**
 * Import a Fireblocks RSA 4096 private key from PEM (PKCS8) format.
 *
 * The returned key is reusable across requests and should be imported once
 * per signer, not per JWT.
 *
 * @param privateKeyPem - RSA 4096 private key in PEM format
 * @returns The imported RS256 signing key
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` when the PEM cannot be parsed
 */
export async function importFireblocksPrivateKey(privateKeyPem: string): Promise<CryptoKey> {
    try {
        return await importPKCS8(normalizePrivateKeyPem(privateKeyPem), 'RS256');
    } catch (error) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            cause: error,
            message: 'Failed to parse Fireblocks RSA private key',
        });
    }
}

/**
 * @param apiKey - Fireblocks API key (used as subject)
 * @param privateKey - RSA signing key from {@link importFireblocksPrivateKey}
 * @param uri - API endpoint path (e.g., "/v1/transactions")
 * @param body - Request body as string (empty string for GET requests)
 * @returns JWT token string
 */
export async function createJwt(apiKey: string, privateKey: CryptoKey, uri: string, body: string): Promise<string> {
    try {
        const bodyHash = await sha256Hex(body);

        const nonce = crypto.randomUUID();

        const now = Math.floor(Date.now() / 1000);
        const issuedAt = now - JWT_SKEW_LEEWAY_SECS;

        const jwt = await new SignJWT({
            bodyHash,
            nonce,
            uri,
        })
            .setProtectedHeader({ alg: 'RS256' })
            .setSubject(apiKey)
            .setIssuedAt(issuedAt)
            .setNotBefore(issuedAt)
            .setExpirationTime(now + JWT_TTL_SECS)
            .sign(privateKey);

        return jwt;
    } catch (error) {
        if (error instanceof Error && error.name === 'SignerError') {
            throw error;
        }
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            cause: error,
            message: 'Failed to create JWT',
        });
    }
}

async function sha256Hex(data: string): Promise<string> {
    const dataBuffer = new TextEncoder().encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    base16Decoder ||= getBase16Decoder();
    return base16Decoder.decode(new Uint8Array(hashBuffer));
}
