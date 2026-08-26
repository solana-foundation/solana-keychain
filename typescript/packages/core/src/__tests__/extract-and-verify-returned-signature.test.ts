import { Address, getAddressDecoder, getAddressEncoder } from '@solana/addresses';
import { generateKeyPair, SignatureBytes, signBytes } from '@solana/keys';
import { describe, expect, it } from 'vitest';

import { extractAndVerifyReturnedSignature } from '../utils.js';

async function createTestKeypair() {
    const keyPair = await generateKeyPair();
    const publicKeyBytes = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const address = getAddressDecoder().decode(new Uint8Array(publicKeyBytes));
    return {
        address,
        sign: (data: Uint8Array) => signBytes(keyPair.privateKey, data),
    };
}

/** A minimal legacy message with one required signer and no instructions. */
function buildMessageBytes(signerAddress: Address): Uint8Array {
    const signerBytes = getAddressEncoder().encode(signerAddress);
    return new Uint8Array([
        1, // numRequiredSignatures
        0, // numReadonlySignedAccounts
        0, // numReadonlyUnsignedAccounts
        1, // static account count (shortU16)
        ...signerBytes,
        ...new Uint8Array(32), // recent blockhash
        0, // instruction count (shortU16)
    ]);
}

/** Serializes a one-signer wire transaction: [sig count][signature][message]. */
function buildWireTransaction(signature: Uint8Array, messageBytes: Uint8Array): Uint8Array {
    return new Uint8Array([1, ...signature, ...messageBytes]);
}

describe('extractAndVerifyReturnedSignature', () => {
    it('returns the signature when the returned transaction carries a valid one', async () => {
        const kp = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const signature = await kp.sign(messageBytes);
        const returnedTransactionBytes = buildWireTransaction(signature, messageBytes);

        const extracted = await extractAndVerifyReturnedSignature({
            originalMessageBytes: messageBytes,
            returnedTransactionBytes,
            signerAddress: kp.address,
        });

        expect(new Uint8Array(extracted)).toStrictEqual(new Uint8Array(signature));
    });

    it('throws SIGNING_FAILED when the address is not a signer of the returned transaction', async () => {
        const kp = await createTestKeypair();
        const other = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const signature = await kp.sign(messageBytes);
        const returnedTransactionBytes = buildWireTransaction(signature, messageBytes);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes: messageBytes,
                returnedTransactionBytes,
                signerAddress: other.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('No signature found'),
        });
    });

    it('throws SIGNING_FAILED when the signer slot holds a default (all-zero) signature', async () => {
        const kp = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const returnedTransactionBytes = buildWireTransaction(new Uint8Array(64), messageBytes);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes: messageBytes,
                returnedTransactionBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('No signature found'),
        });
    });

    it('throws SIGNING_FAILED when the signature does not verify against the original message', async () => {
        const kp = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const signature = await kp.sign(messageBytes);
        const corrupted = new Uint8Array(signature);
        corrupted[0] ^= 0xff;
        const returnedTransactionBytes = buildWireTransaction(corrupted, messageBytes);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes: messageBytes,
                returnedTransactionBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('Signature verification failed'),
        });
    });

    it('verifies against the ORIGINAL message bytes, not the returned ones', async () => {
        const kp = await createTestKeypair();
        const originalMessageBytes = buildMessageBytes(kp.address);
        const tamperedMessageBytes = new Uint8Array(originalMessageBytes);
        tamperedMessageBytes[tamperedMessageBytes.length - 2] ^= 0xff;
        const signature = await kp.sign(tamperedMessageBytes);
        const returnedTransactionBytes = buildWireTransaction(signature, tamperedMessageBytes);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes,
                returnedTransactionBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('Signature verification failed'),
        });
    });

    it('throws SIGNING_FAILED for malformed transaction bytes', async () => {
        const kp = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes: messageBytes,
                returnedTransactionBytes: new Uint8Array([7, 1, 2, 3]),
                signerAddress: kp.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('Failed to decode returned signed transaction'),
        });
    });

    it('throws when the abort signal is already aborted', async () => {
        const kp = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const signature = await kp.sign(messageBytes);
        const returnedTransactionBytes = buildWireTransaction(signature, messageBytes);
        const controller = new AbortController();
        controller.abort(new Error('aborted before verification'));

        await expect(
            extractAndVerifyReturnedSignature({
                abortSignal: controller.signal,
                originalMessageBytes: messageBytes,
                returnedTransactionBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toThrow('aborted before verification');
    });

    it('rejects a signature that verifies for a different signer in the returned transaction', async () => {
        const kp = await createTestKeypair();
        const other = await createTestKeypair();
        const messageBytes = buildMessageBytes(kp.address);
        const foreignSignature = (await other.sign(messageBytes)) as SignatureBytes;
        const returnedTransactionBytes = buildWireTransaction(foreignSignature, messageBytes);

        await expect(
            extractAndVerifyReturnedSignature({
                originalMessageBytes: messageBytes,
                returnedTransactionBytes,
                signerAddress: kp.address,
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_SIGNING_FAILED',
            message: expect.stringContaining('Signature verification failed'),
        });
    });
});
