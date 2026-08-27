import { p256 } from '@noble/curves/nist.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import { base64UrlDecoder, SignerErrorCode, throwSignerError } from '@solana/keychain-core';

/**
 * Configuration for ApiKeyStamper
 */
export interface ApiKeyStamperConfig {
    /** Turnkey API private key in hex format (32 bytes) */
    apiPrivateKey: string;
    /** Turnkey API public key in compressed hex format (33 bytes) */
    apiPublicKey: string;
}

/**
 * Result of stamping operation
 */
export interface StampResult {
    /** Header name (always "X-Stamp") */
    stampHeaderName: string;
    /** Base64url-encoded stamp value */
    stampHeaderValue: string;
}

/**
 * Validate Turnkey API key material: both keys must be valid hex, the public
 * key must be a 33-byte compressed P-256 point that decompresses to a valid
 * curve point, and the private key must be 32 bytes.
 *
 * @throws `CONFIG_ERROR` when the key material is invalid.
 */
function validateApiKeyMaterial(privateKeyHex: string, publicKeyHex: string): void {
    let publicKeyBytes: Uint8Array;
    let privateKeyBytes: Uint8Array;
    try {
        publicKeyBytes = hexToBytes(publicKeyHex);
        privateKeyBytes = hexToBytes(privateKeyHex);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Turnkey API keys must be valid hex strings',
        });
    }

    if (publicKeyBytes.length !== 33) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Public key must be 33 bytes (compressed P-256 format), got ${publicKeyBytes.length}`,
        });
    }

    if (privateKeyBytes.length !== 32) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Private key must be 32 bytes, got ${privateKeyBytes.length}`,
        });
    }

    try {
        p256.Point.fromHex(publicKeyHex);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Public key is not a valid P-256 point',
        });
    }
}

/**
 * ApiKeyStamper creates X-Stamp headers for Turnkey API authentication
 * Uses P256 (secp256r1) ECDSA signing with SHA-256
 *
 * Key material is validated once in the constructor, so `stamp()` only signs.
 */
export class ApiKeyStamper {
    private readonly apiPrivateKey: string;
    private readonly apiPublicKey: string;

    /**
     * @throws `CONFIG_ERROR` when the API key material is invalid.
     */
    constructor(config: ApiKeyStamperConfig) {
        validateApiKeyMaterial(config.apiPrivateKey, config.apiPublicKey);
        this.apiPrivateKey = config.apiPrivateKey;
        this.apiPublicKey = config.apiPublicKey;
    }

    /**
     * Create an X-Stamp header for the given message
     * @param message - The message to sign (typically JSON stringified request body)
     * @returns Stamp result with header name and value
     */
    stamp(message: string): StampResult {
        try {
            const messageBytes = new TextEncoder().encode(message);
            const privateKeyBytes = hexToBytes(this.apiPrivateKey);
            const signatureDerBytes = p256.sign(messageBytes, privateKeyBytes, {
                format: 'der',
                prehash: true,
            });
            const signatureHex = bytesToHex(signatureDerBytes);

            // Same structure as the Turnkey SDK stamp.
            const stamp = {
                publicKey: this.apiPublicKey,
                scheme: 'SIGNATURE_SCHEME_TK_API_P256',
                signature: signatureHex,
            };

            const stampJson = JSON.stringify(stamp);
            const stampBase64url = base64UrlDecoder(new TextEncoder().encode(stampJson));

            return {
                stampHeaderName: 'X-Stamp',
                stampHeaderValue: stampBase64url,
            };
        } catch (error) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Failed to create authentication stamp',
            });
        }
    }
}
