import { getAddressDecoder } from '@solana/addresses';
import { generateKeyPair, signBytes, SignatureBytes } from '@solana/keys';
import { describe, expect, it } from 'vitest';

import { assertSignatureValid } from '../utils.js';

async function createTestKeypair() {
    const keyPair = await generateKeyPair();
    const publicKeyBytes = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const address = getAddressDecoder().decode(new Uint8Array(publicKeyBytes));
    return {
        address,
        sign: (data: Uint8Array) => signBytes(keyPair.privateKey, data),
    };
}

describe('assertSignatureValid', () => {
    it('does not throw for a valid signature', async () => {
        const kp = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp.sign(data);

        await expect(assertSignatureValid({ data, signature, signerAddress: kp.address })).resolves.toBeUndefined();
    });

    it('verifies over the bytes a shared, offset view holds', async () => {
        const kp = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp.sign(data);
        const shared = new Uint8Array(new SharedArrayBuffer(data.length + 8));
        shared.set(data, 8);

        await expect(
            assertSignatureValid({ data: shared.subarray(8), signature, signerAddress: kp.address }),
        ).resolves.toBeUndefined();
    });

    it('throws SIGNING_FAILED for a corrupted signature', async () => {
        const kp = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp.sign(data);

        const corrupted = new Uint8Array(signature);
        corrupted[0] ^= 0xff;

        await expect(
            assertSignatureValid({
                data,
                signature: corrupted as SignatureBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toThrow('Signature verification failed');
    });

    it('throws SIGNING_FAILED when data differs', async () => {
        const kp = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp.sign(data);

        const differentData = new Uint8Array([5, 6, 7, 8]);

        await expect(
            assertSignatureValid({
                data: differentData,
                signature,
                signerAddress: kp.address,
            }),
        ).rejects.toThrow('Signature verification failed');
    });

    it('throws SIGNING_FAILED when address does not match signer', async () => {
        const kp1 = await createTestKeypair();
        const kp2 = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp1.sign(data);

        await expect(
            assertSignatureValid({
                data,
                signature,
                signerAddress: kp2.address,
            }),
        ).rejects.toThrow('Signature verification failed');
    });

    // Zcash ZIP-215 vectors the runtime accepts and WebCrypto rejects.
    it.each([
        [
            '0100000000000000000000000000000000000000000000000000000000000000',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000',
        ],
        [
            '0100000000000000000000000000000000000000000000000000000000000000',
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000',
        ],
        [
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            '01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        ],
    ])('accepts the ZIP-215 vector for %s', async (publicKeyHex, signatureHex) => {
        const publicKeyBytes = unhex(publicKeyHex);
        const signature = unhex(signatureHex) as SignatureBytes;
        const data = new TextEncoder().encode('Zcash');

        const webCryptoKey = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, [
            'verify',
        ]);
        expect(await crypto.subtle.verify({ name: 'Ed25519' }, webCryptoKey, signature, data)).toBe(false);

        await expect(
            assertSignatureValid({ data, signature, signerAddress: getAddressDecoder().decode(publicKeyBytes) }),
        ).resolves.toBeUndefined();
    });
});

function unhex(hex: string): Uint8Array {
    return Uint8Array.from(hex.match(/../g)!.map(byte => parseInt(byte, 16)));
}
