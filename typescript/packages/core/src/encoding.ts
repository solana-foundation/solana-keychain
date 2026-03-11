import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;

/**
 * Encode a base64url string to bytes (RFC 4648 §5).
 * Follows kit codec naming: Encoder = string → bytes.
 */
export function base64UrlEncoder(value: string): Uint8Array {
    base64Encoder ||= getBase64Encoder();
    const m = value.length % 4;
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
