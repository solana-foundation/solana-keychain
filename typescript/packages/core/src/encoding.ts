import { getBase58Decoder, getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';

import { SignerErrorCode, throwSignerError } from './errors.js';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;
let base58Decoder: ReturnType<typeof getBase58Decoder> | undefined;

/**
 * Encode a base64url string to bytes (RFC 4648 §5).
 * Follows kit codec naming: Encoder = string → bytes.
 */
export function base64UrlEncoder(value: string): Uint8Array {
    base64Encoder ||= getBase64Encoder();
    const m = value.length % 4;
    if (m === 1) {
        throwSignerError(SignerErrorCode.SERIALIZATION_ERROR, {
            message: 'Invalid base64url string: length leaves a single trailing character with no valid padding',
        });
    }
    const base64Value = value
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(value.length + (m === 0 ? 0 : 4 - m), '=');
    return new Uint8Array(base64Encoder.encode(base64Value));
}

/**
 * Decode bytes to a base64url string (RFC 4648 §5).
 * Follows kit codec naming: Decoder = bytes → string.
 */
export function base64UrlDecoder(bytes: Uint8Array): string {
    base64Decoder ||= getBase64Decoder();
    return base64Decoder.decode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * DER SubjectPublicKeyInfo header for an Ed25519 key: SEQUENCE, AlgorithmIdentifier
 * with OID 1.3.101.112, then a 33-byte BIT STRING with zero unused bits.
 */
const ED25519_SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/**
 * Render a raw 32-byte Ed25519 public key as a Solana address.
 * Returns undefined for any other length.
 */
export function addressFromEd25519Key(key: Uint8Array): string | undefined {
    if (key.length !== 32) {
        return undefined;
    }
    base58Decoder ||= getBase58Decoder();
    return base58Decoder.decode(key);
}

/**
 * Render the Solana address carried by a DER-encoded Ed25519 SubjectPublicKeyInfo.
 * Returns undefined when the bytes are not an Ed25519 SPKI.
 */
export function addressFromSpkiDer(der: Uint8Array): string | undefined {
    if (der.length !== ED25519_SPKI_PREFIX.length + 32) {
        return undefined;
    }
    if (ED25519_SPKI_PREFIX.some((byte, index) => der[index] !== byte)) {
        return undefined;
    }
    return addressFromEd25519Key(der.subarray(ED25519_SPKI_PREFIX.length));
}

/**
 * Render the Solana address carried by a PEM-encoded Ed25519 SubjectPublicKeyInfo.
 * Returns undefined when the PEM does not decode to an Ed25519 SPKI.
 */
export function addressFromSpkiPem(pem: string): string | undefined {
    const body = pem
        .split('\n')
        .filter(line => !line.startsWith('-----'))
        .join('')
        .replace(/\s/g, '');
    base64Encoder ||= getBase64Encoder();
    try {
        return addressFromSpkiDer(new Uint8Array(base64Encoder.encode(body)));
    } catch {
        return undefined;
    }
}
