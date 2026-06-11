import * as nodeCrypto from 'node:crypto';

import { describe, it, expect } from 'vitest';

import { importDfnsCredentialKey, p1363ToDer } from '../auth.js';

/**
 * Parse a DER `SEQUENCE { INTEGER r, INTEGER s }` into its two unsigned
 * big-endian components (with any DER `0x00` sign-padding stripped).
 */
function parseDerEcdsa(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
    expect(der[0]).toBe(0x30); // SEQUENCE
    expect(der[1]).toBe(der.length - 2); // single-byte length matches body
    let offset = 2;

    const readInteger = (): Uint8Array => {
        expect(der[offset]).toBe(0x02); // INTEGER
        const len = der[offset + 1] ?? 0;
        let content = der.subarray(offset + 2, offset + 2 + len);
        offset += 2 + len;
        // Strip a single leading 0x00 sign byte if present.
        if (content.length > 1 && content[0] === 0x00) {
            content = content.subarray(1);
        }
        return content;
    };

    const r = readInteger();
    const s = readInteger();
    expect(offset).toBe(der.length); // exactly two integers, no trailing bytes
    return { r, s };
}

/** Left-pad (or strip leading zeros) to exactly `length` bytes. */
function toFixed(bytes: Uint8Array, length: number): Uint8Array {
    const out = new Uint8Array(length);
    out.set(bytes.subarray(Math.max(0, bytes.length - length)), length - Math.min(length, bytes.length));
    return out;
}

describe('p1363ToDer', () => {
    it('encodes a 64-byte raw r||s as a DER SEQUENCE of two INTEGERs', () => {
        const r = new Uint8Array(32).fill(0x01);
        const s = new Uint8Array(32).fill(0x02);
        const raw = new Uint8Array([...r, ...s]);

        const der = p1363ToDer(raw);
        expect(der[0]).toBe(0x30);
        const parsed = parseDerEcdsa(der);
        expect(toFixed(parsed.r, 32)).toStrictEqual(r);
        expect(toFixed(parsed.s, 32)).toStrictEqual(s);
    });

    it('prepends a 0x00 byte when the high bit of r or s is set', () => {
        const r = new Uint8Array(32);
        r[0] = 0x80; // high bit set -> must be padded to stay positive
        const s = new Uint8Array(32);
        s[0] = 0x7f; // high bit clear -> no padding
        const raw = new Uint8Array([...r, ...s]);

        const der = p1363ToDer(raw);
        // r INTEGER content starts right after the outer SEQUENCE header (2 bytes)
        // + r INTEGER header (2 bytes).
        expect(der[2]).toBe(0x02); // INTEGER tag for r
        expect(der[3]).toBe(33); // 32 bytes + 1 sign byte
        expect(der[4]).toBe(0x00); // sign-padding byte
        expect(der[5]).toBe(0x80);

        const parsed = parseDerEcdsa(der);
        expect(toFixed(parsed.r, 32)).toStrictEqual(r);
        expect(toFixed(parsed.s, 32)).toStrictEqual(s);
    });

    it('strips leading zero bytes to a minimal-length encoding', () => {
        const r = new Uint8Array(32);
        r[31] = 0x05; // value 5, lots of leading zeros
        const s = new Uint8Array(32).fill(0x33);
        const raw = new Uint8Array([...r, ...s]);

        const der = p1363ToDer(raw);
        const parsed = parseDerEcdsa(der);
        expect(parsed.r).toStrictEqual(new Uint8Array([0x05])); // minimal length
        expect(toFixed(parsed.s, 32)).toStrictEqual(s);
    });

    it('rejects odd-length and empty inputs', () => {
        expect(() => p1363ToDer(new Uint8Array(0))).toThrow(/even-length/);
        expect(() => p1363ToDer(new Uint8Array(63))).toThrow(/even-length/);
    });
});

describe('importDfnsCredentialKey', () => {
    const clientData = new TextEncoder().encode('{"challenge":"abc","type":"key.get"}');

    it('produces a DER-encoded signature for a P-256 (prime256v1) credential that node verifies', async () => {
        const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

        const credentialKey = await importDfnsCredentialKey(pem);
        const signature = await credentialKey.sign(clientData);

        // DER SEQUENCE tag.
        expect(signature[0]).toBe(0x30);
        // Parses as SEQUENCE of exactly two INTEGERs.
        expect(() => parseDerEcdsa(signature)).not.toThrow();

        // node:crypto verifies the DER signature (dsaEncoding 'der' is the default).
        const verified = nodeCrypto.verify('sha256', clientData, { dsaEncoding: 'der', key: publicKey }, signature);
        expect(verified).toBe(true);
    });

    it('passes Ed25519 signatures through unchanged (64 bytes, no DER wrapping)', async () => {
        const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ed25519');
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

        const credentialKey = await importDfnsCredentialKey(pem);
        const signature = await credentialKey.sign(clientData);

        expect(signature.length).toBe(64); // raw Ed25519 signature, not DER-wrapped
        const verified = nodeCrypto.verify(null, clientData, publicKey, signature);
        expect(verified).toBe(true);
    });

    it('produces an RSASSA-PKCS1-v1_5/SHA-256 signature for an RSA credential that node verifies', async () => {
        const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

        const credentialKey = await importDfnsCredentialKey(pem);
        const signature = await credentialKey.sign(clientData);

        expect(signature.length).toBe(256); // 2048-bit RSA signature
        const verified = nodeCrypto.verify('sha256', clientData, publicKey, signature);
        expect(verified).toBe(true);
    });

    it('reuses the imported key across multiple sign calls', async () => {
        const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ed25519');
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

        const credentialKey = await importDfnsCredentialKey(pem);
        const first = await credentialKey.sign(clientData);
        const second = await credentialKey.sign(new TextEncoder().encode('other payload'));

        expect(nodeCrypto.verify(null, clientData, publicKey, first)).toBe(true);
        expect(nodeCrypto.verify(null, new TextEncoder().encode('other payload'), publicKey, second)).toBe(true);
    });

    it('throws INVALID_PRIVATE_KEY for a key that no supported algorithm can import', async () => {
        await expect(importDfnsCredentialKey('not-a-pem-key')).rejects.toMatchObject({
            code: 'SIGNER_INVALID_PRIVATE_KEY',
            message: expect.stringContaining('not a supported'),
        });
    });
});
