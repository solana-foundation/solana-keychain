import { p256 } from '@noble/curves/nist.js';
import { numberToBytesBE } from '@noble/curves/utils.js';
import { SignerErrorCode, throwSignerError } from '@solana-keychain/core';
import * as crypto from 'crypto';

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
 * Convert hex string to base64url with padding to ensure exact byte length
 */
function hexToBase64url(hex: string, paddedLength: number = 32): string {
    // Ensure hex string has even length
    const evenHex = hex.length % 2 === 0 ? hex : '0' + hex;
    const bytes = Buffer.from(evenHex, 'hex');

    // Pad with leading zeros if needed
    if (bytes.length < paddedLength) {
        const padded = Buffer.alloc(paddedLength);
        bytes.copy(padded, paddedLength - bytes.length);
        return padded.toString('base64url');
    } else if (bytes.length > paddedLength) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `API to JWK conversion failed: Hex string too long: ${bytes.length} bytes (max ${paddedLength})`,
        });
    }

    return bytes.toString('base64url');
}

/**
 * Convert Turnkey API key pair to JWK format
 * Based on Turnkey's official SDK implementation
 */
function convertTurnkeyApiKeyToJwk(privateKeyHex: string, publicKeyHex: string): crypto.JsonWebKey {
    const JWK_MEMBER_BYTE_LENGTH = 32; // P-256 uses 32-byte coordinates

    // Validate public key length (33 bytes for compressed P-256)
    const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
    if (publicKeyBytes.length !== 33) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `API to JWK conversion failed: Public key must be 33 bytes (compressed P-256 format), got ${publicKeyBytes.length}`,
        });
    }

    // Validate private key length (32 bytes)
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    if (privateKeyBytes.length !== 32) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `API to JWK conversion failed: Private key must be 32 bytes, got ${privateKeyBytes.length}`,
        });
    }

    try {
        // Decompress the P-256 public key point to get x and y coordinates
        const point = p256.Point.fromHex(publicKeyHex);
        const affinePoint = point.toAffine();

        // Convert coordinates to padded base64url (exactly 32 bytes each)
        const xBytes = numberToBytesBE(affinePoint.x, JWK_MEMBER_BYTE_LENGTH);
        const yBytes = numberToBytesBE(affinePoint.y, JWK_MEMBER_BYTE_LENGTH);

        // Create JWK with all members padded to 32 bytes
        return {
            crv: 'P-256',
            d: hexToBase64url(privateKeyHex, JWK_MEMBER_BYTE_LENGTH),
            ext: true,
            kty: 'EC',
            x: Buffer.from(xBytes).toString('base64url'),
            y: Buffer.from(yBytes).toString('base64url'),
        };
    } catch (e) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: e,
            message: 'Failed to convert API key to JWK',
        });
    }
}

/**
 * ApiKeyStamper creates X-Stamp headers for Turnkey API authentication
 * Uses P256 (secp256r1) ECDSA signing with SHA-256
 */
export class ApiKeyStamper {
    private readonly apiPrivateKey: string;
    private readonly apiPublicKey: string;

    constructor(config: ApiKeyStamperConfig) {
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
            // Convert Turnkey API key to JWK format
            const jwk = convertTurnkeyApiKeyToJwk(this.apiPrivateKey, this.apiPublicKey);

            // Create private key object from JWK
            const privateKeyObject = crypto.createPrivateKey({
                format: 'jwk',
                key: jwk,
            });

            // Sign the message with SHA-256 (produces DER-encoded signature)
            const sign = crypto.createSign('SHA256');
            sign.write(Buffer.from(message));
            sign.end();

            const signatureHex = sign.sign(privateKeyObject, 'hex');

            // Create stamp object (same structure as Turnkey SDK)
            const stamp = {
                publicKey: this.apiPublicKey,
                scheme: 'SIGNATURE_SCHEME_TK_API_P256',
                signature: signatureHex,
            };

            // Encode as base64url (RFC 4648 §5)
            const stampJson = JSON.stringify(stamp);
            const stampBase64url = Buffer.from(stampJson).toString('base64url');

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
