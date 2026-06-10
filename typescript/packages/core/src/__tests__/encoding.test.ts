import { describe, expect, it } from 'vitest';

import { base64UrlDecoder, base64UrlEncoder } from '../encoding.js';

describe('base64UrlEncoder', () => {
    it('round-trips bytes through the decoder', () => {
        const bytes = new Uint8Array([1, 2, 3, 4, 5]);
        const encoded = base64UrlDecoder(bytes);
        expect([...base64UrlEncoder(encoded)]).toEqual([...bytes]);
    });

    it('accepts unpadded base64url whose length is a multiple of 4 minus 2 or 3', () => {
        // length % 4 === 2 ('AA' -> 1 byte) and === 3 ('AAA' -> 2 bytes) are valid
        expect(base64UrlEncoder('AA')).toHaveLength(1);
        expect(base64UrlEncoder('AAA')).toHaveLength(2);
    });

    it('rejects an invalid base64url string with a trailing single character', () => {
        // length % 4 === 1 cannot be padded to a valid base64 group
        expect(() => base64UrlEncoder('AAAAA')).toThrowError(
            expect.objectContaining({ code: 'SIGNER_SERIALIZATION_ERROR' }),
        );
    });
});
