import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';

const base64Encoder = getBase64Encoder();
const base64Decoder = getBase64Decoder();

/**
 * Encode bytes to a base64url string (RFC 4648 §5).
 * Uses kit's base64 codec with URL-safe character substitution.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
    return base64Decoder.decode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string (RFC 4648 §5) to bytes.
 * Uses kit's base64 codec with URL-safe character substitution.
 */
export function base64UrlDecode(value: string): Uint8Array {
    const m = value.length % 4;
    const base64Value = value
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(value.length + (m === 0 ? 0 : 4 - m), '=');
    return new Uint8Array(base64Encoder.encode(base64Value));
}
