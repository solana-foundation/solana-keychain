import { describe, expect, it } from 'vitest';

import { getBase64Decoder } from '@solana/codecs-strings';

import {
    addressFromEd25519Key,
    addressFromSpkiDer,
    addressFromSpkiPem,
    base64UrlDecoder,
    base64UrlEncoder,
} from '../encoding.js';

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

const SYSTEM_PROGRAM_KEY = new Uint8Array(32);
const SYSTEM_PROGRAM_ADDRESS = '11111111111111111111111111111111';

function spkiDer(key: Uint8Array): Uint8Array {
    return new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...key]);
}

describe('addressFromEd25519Key', () => {
    it('renders a 32-byte key as a base58 address', () => {
        expect(addressFromEd25519Key(SYSTEM_PROGRAM_KEY)).toBe(SYSTEM_PROGRAM_ADDRESS);
    });

    it('rejects any other length', () => {
        expect(addressFromEd25519Key(new Uint8Array(31))).toBeUndefined();
        expect(addressFromEd25519Key(new Uint8Array(33))).toBeUndefined();
    });
});

describe('addressFromSpkiDer', () => {
    it('extracts the address from an Ed25519 SubjectPublicKeyInfo', () => {
        expect(addressFromSpkiDer(spkiDer(SYSTEM_PROGRAM_KEY))).toBe(SYSTEM_PROGRAM_ADDRESS);
    });

    it('rejects DER that is not an Ed25519 SubjectPublicKeyInfo', () => {
        const foreignOid = spkiDer(SYSTEM_PROGRAM_KEY);
        foreignOid[8] = 0x71;
        expect(addressFromSpkiDer(foreignOid)).toBeUndefined();
        expect(addressFromSpkiDer(new Uint8Array(0))).toBeUndefined();
    });
});

describe('addressFromSpkiPem', () => {
    it('extracts the address from a PEM-wrapped SubjectPublicKeyInfo', () => {
        const body = getBase64Decoder().decode(spkiDer(SYSTEM_PROGRAM_KEY));
        const pem = `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
        expect(addressFromSpkiPem(pem)).toBe(SYSTEM_PROGRAM_ADDRESS);
    });

    it('rejects text that is not a PEM-encoded key', () => {
        expect(addressFromSpkiPem('not a pem')).toBeUndefined();
    });
});
