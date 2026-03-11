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

    it('throws SIGNING_FAILED for a corrupted signature', async () => {
        const kp = await createTestKeypair();
        const data = new Uint8Array([1, 2, 3, 4]);
        const signature = await kp.sign(data);

        // Corrupt the first byte
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
});
