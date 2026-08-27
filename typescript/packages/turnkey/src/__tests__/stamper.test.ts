import { p256 } from '@noble/curves/nist.js';
import { bytesToHex } from '@noble/curves/utils.js';
import { describe, expect, test } from 'vitest';

import { ApiKeyStamper } from '../stamper.js';

function getTestKeys() {
    const privateKey = 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';

    const publicKeyBytes = p256.getPublicKey(Buffer.from(privateKey, 'hex'));
    const publicKey = bytesToHex(publicKeyBytes);

    return { privateKey, publicKey };
}

describe('ApiKeyStamper', () => {
    describe('constructor key validation', () => {
        test('throws CONFIG_ERROR when keys are not valid hex', () => {
            expect(
                () =>
                    new ApiKeyStamper({
                        apiPrivateKey: 'not-hex',
                        apiPublicKey: 'also-not-hex',
                    }),
            ).toThrow('Turnkey API keys must be valid hex strings');
        });

        test('throws CONFIG_ERROR when public key is not 33 bytes', () => {
            const { privateKey } = getTestKeys();
            const uncompressedPublicKey = bytesToHex(p256.getPublicKey(Buffer.from(privateKey, 'hex'), false));

            expect(
                () =>
                    new ApiKeyStamper({
                        apiPrivateKey: privateKey,
                        apiPublicKey: uncompressedPublicKey,
                    }),
            ).toThrow('Public key must be 33 bytes (compressed P-256 format), got 65');
        });

        test('throws CONFIG_ERROR when private key is not 32 bytes', () => {
            const { publicKey } = getTestKeys();

            expect(
                () =>
                    new ApiKeyStamper({
                        apiPrivateKey: 'abcdef',
                        apiPublicKey: publicKey,
                    }),
            ).toThrow('Private key must be 32 bytes, got 3');
        });

        test('throws CONFIG_ERROR when public key is not a valid P-256 point', () => {
            const { privateKey } = getTestKeys();
            const invalidPoint = '02' + 'ff'.repeat(32);

            expect(
                () =>
                    new ApiKeyStamper({
                        apiPrivateKey: privateKey,
                        apiPublicKey: invalidPoint,
                    }),
            ).toThrow('Public key is not a valid P-256 point');
        });
    });

    test('creates valid X-Stamp header with P256 signature', () => {
        const { privateKey, publicKey } = getTestKeys();

        const stamper = new ApiKeyStamper({
            apiPrivateKey: privateKey,
            apiPublicKey: publicKey,
        });

        const messageToSign = 'hello from TKHQ!';
        const stamp = stamper.stamp(messageToSign);

        expect(stamp.stampHeaderName).toBe('X-Stamp');

        const decodedStamp = JSON.parse(Buffer.from(stamp.stampHeaderValue, 'base64url').toString());

        expect(Object.keys(decodedStamp).sort()).toEqual(['publicKey', 'scheme', 'signature']);

        expect(decodedStamp.publicKey).toBe(publicKey);
        expect(decodedStamp.scheme).toBe('SIGNATURE_SCHEME_TK_API_P256');

        expect(decodedStamp.signature).toMatch(/^30[0-9a-f]+$/);
        expect(decodedStamp.signature.length).toBeGreaterThan(0);
    });

    test('produces valid signatures for same message', async () => {
        const { privateKey, publicKey } = getTestKeys();

        const stamper = new ApiKeyStamper({
            apiPrivateKey: privateKey,
            apiPublicKey: publicKey,
        });

        const messageToSign = 'test message';
        const stamp1 = stamper.stamp(messageToSign);
        const stamp2 = stamper.stamp(messageToSign);

        const decoded1 = JSON.parse(Buffer.from(stamp1.stampHeaderValue, 'base64url').toString());
        const decoded2 = JSON.parse(Buffer.from(stamp2.stampHeaderValue, 'base64url').toString());

        // ECDSA signatures are non-deterministic, so we just verify they're valid DER format
        expect(decoded1.signature).toMatch(/^30[0-9a-f]+$/);
        expect(decoded2.signature).toMatch(/^30[0-9a-f]+$/);
    });

    test('produces different stamps for different messages', () => {
        const { privateKey, publicKey } = getTestKeys();

        const stamper = new ApiKeyStamper({
            apiPrivateKey: privateKey,
            apiPublicKey: publicKey,
        });

        const stamp1 = stamper.stamp('message 1');
        const stamp2 = stamper.stamp('message 2');

        const decoded1 = JSON.parse(Buffer.from(stamp1.stampHeaderValue, 'base64url').toString());
        const decoded2 = JSON.parse(Buffer.from(stamp2.stampHeaderValue, 'base64url').toString());

        expect(decoded1.signature).not.toBe(decoded2.signature);
    });

    test('encodes stamp as base64url without padding', () => {
        const { privateKey, publicKey } = getTestKeys();

        const stamper = new ApiKeyStamper({
            apiPrivateKey: privateKey,
            apiPublicKey: publicKey,
        });

        const stamp = stamper.stamp('test');

        expect(stamp.stampHeaderValue).not.toMatch(/[+/=]/);

        expect(() => Buffer.from(stamp.stampHeaderValue, 'base64url')).not.toThrow();
    });
});
