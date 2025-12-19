import { SignerErrorCode, throwSignerError } from '@solana-keychain/core';
import { importPKCS8, SignJWT } from 'jose';

/**
 * Create a JWT for Fireblocks API authentication
 *
 * @param apiKey - Fireblocks API key (used as subject)
 * @param privateKeyPem - RSA 4096 private key in PEM format
 * @param uri - API endpoint path (e.g., "/v1/transactions")
 * @param body - Request body as string (empty string for GET requests)
 * @returns JWT token string
 */
export async function createJwt(apiKey: string, privateKeyPem: string, uri: string, body: string): Promise<string> {
    try {
        // Import the RSA private key
        const privateKey = await importPKCS8(privateKeyPem, 'RS256');

        // SHA256 hash of body
        const bodyHash = await sha256Hex(body);

        // Generate nonce (UUID v4)
        const nonce = crypto.randomUUID();

        const now = Math.floor(Date.now() / 1000);

        const jwt = await new SignJWT({
            bodyHash,
            nonce,
            uri,
        })
            .setProtectedHeader({ alg: 'RS256' })
            .setSubject(apiKey)
            .setIssuedAt(now)
            .setExpirationTime(now + 30)
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

/**
 * Compute SHA256 hash and return as hex string
 */
async function sha256Hex(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
