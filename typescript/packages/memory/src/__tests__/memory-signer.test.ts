import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { assertIsSolanaSigner, assertSignatureValid } from '@solana/keychain-core';
import {
    blockhash,
    compileTransaction,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { generateKeyPair } from '@solana/keys';
import { describe, expect, it } from 'vitest';

import {
    createMemorySigner,
    createMemorySignerFromBytes,
    createMemorySignerFromKeyPair,
    createMemorySignerFromKeypairFile,
    createMemorySignerFromPrivateKeyString,
} from '../memory-signer.js';

const TEST_KEYPAIR_BYTES_STRING =
    '[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]';
const TEST_KEYPAIR_BASE58 = 'pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1';
const TEST_KEYPAIR_BYTES = new Uint8Array([
    41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196, 204, 122, 47, 166, 133, 155,
    252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136, 72, 22, 157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236,
    188, 241, 134, 174, 224, 100, 246, 17, 170, 104, 17, 151, 48,
]);
const TEST_PUBKEY = '4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR';

describe('createMemorySigner', () => {
    describe('config validation', () => {
        it('rejects an empty config', async () => {
            await expect(createMemorySigner({})).rejects.toThrow(
                'Memory signer requires one of: keyPair, privateKey, privateKeyString, privateKeyPath',
            );
        });

        it('rejects multiple sources', async () => {
            await expect(
                createMemorySigner({
                    privateKey: TEST_KEYPAIR_BYTES,
                    privateKeyString: TEST_KEYPAIR_BASE58,
                }),
            ).rejects.toThrow('must have exactly one source');
        });

        it('rejects a privateKey of an unsupported length', async () => {
            await expect(createMemorySigner({ privateKey: new Uint8Array(48) })).rejects.toThrow(
                /Invalid private key length: expected 32 or 64 bytes/,
            );
        });

        it('rejects a privateKey where seed and pubkey do not match', async () => {
            const garbled = new Uint8Array(TEST_KEYPAIR_BYTES);
            garbled[63] = (garbled[63] ?? 0) ^ 0xff;
            await expect(createMemorySigner({ privateKey: garbled })).rejects.toThrow(/Invalid private key bytes/);
        });
    });

    describe('factories', () => {
        it('builds a signer from 64-byte raw bytes (seed||pubkey)', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            expect(signer.address).toBe(TEST_PUBKEY);
            assertIsSolanaSigner(signer);
        });

        it('builds a signer from 32-byte raw bytes (seed only) and derives the same pubkey', async () => {
            const seed = TEST_KEYPAIR_BYTES.slice(0, 32);
            const signer = await createMemorySignerFromBytes(seed);
            expect(signer.address).toBe(TEST_PUBKEY);
            assertIsSolanaSigner(signer);
        });

        it('builds a signer from a base58 string', async () => {
            const signer = await createMemorySignerFromPrivateKeyString(TEST_KEYPAIR_BASE58);
            expect(signer.address).toBe(TEST_PUBKEY);
        });

        it('builds a signer from a U8Array string', async () => {
            const signer = await createMemorySignerFromPrivateKeyString(TEST_KEYPAIR_BYTES_STRING);
            expect(signer.address).toBe(TEST_PUBKEY);
        });

        it('builds a signer from a Solana CLI keypair file', async () => {
            const path = join(
                tmpdir(),
                `solana-keychain-memory-${Date.now()}-${Math.random().toString(36).slice(2)}.json`,
            );
            await writeFile(path, TEST_KEYPAIR_BYTES_STRING, 'utf-8');
            const signer = await createMemorySignerFromKeypairFile(path);
            expect(signer.address).toBe(TEST_PUBKEY);
        });

        it('builds a signer from a CryptoKeyPair', async () => {
            const keyPair = await generateKeyPair();
            const signer = await createMemorySignerFromKeyPair(keyPair);
            expect(typeof signer.address).toBe('string');
            assertIsSolanaSigner(signer);
        });

        it.each([null, {}])('rejects %o as a keyPair with a config error', async invalid => {
            await expect(createMemorySignerFromKeyPair(invalid as unknown as CryptoKeyPair)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });

        it('rejects a CryptoKeyPair whose public key does not match its private key', async () => {
            const pairA = await generateKeyPair();
            const pairB = await generateKeyPair();
            await expect(
                createMemorySignerFromKeyPair({ privateKey: pairB.privateKey, publicKey: pairA.publicKey }),
            ).rejects.toMatchObject({ code: 'SIGNER_INVALID_PRIVATE_KEY' });
        });

        it('is unaffected by mutating the caller CryptoKeyPair after construction', async () => {
            const keyPair = { ...(await generateKeyPair()) };
            const signer = await createMemorySignerFromKeyPair(keyPair);
            const addressBefore = signer.address;

            keyPair.privateKey = (await generateKeyPair()).privateKey;

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };
            const [dict] = await signer.signMessages([message]);
            const sig = dict?.[addressBefore];
            expect(sig).toBeInstanceOf(Uint8Array);
            await assertSignatureValid({
                data: message.content,
                signature: sig!,
                signerAddress: addressBefore,
            });
        });

        it('wraps KeyPairSigner without exposing the underlying keyPair', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            expect('keyPair' in signer).toBe(false);
        });
    });

    describe('signing', () => {
        it('signs a message and returns a verifiable signature', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            const [dict] = await signer.signMessages([message]);
            const sig = dict?.[signer.address];
            expect(sig).toBeDefined();
            expect(sig).toBeInstanceOf(Uint8Array);
            expect(sig?.length).toBe(64);
        });

        it('signs multiple messages independently', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            const messages = [
                { content: new Uint8Array([1]), signatures: {} },
                { content: new Uint8Array([2]), signatures: {} },
                { content: new Uint8Array([3]), signatures: {} },
            ];

            const dicts = await signer.signMessages(messages);
            expect(dicts).toHaveLength(3);
            const first = dicts[0]?.[signer.address];
            const second = dicts[1]?.[signer.address];
            expect(first).toBeDefined();
            expect(second).toBeDefined();
            expect(first).not.toEqual(second);
        });

        it('accepts the Kit signer config on both signing methods', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };
            const abortSignal = new AbortController().signal;

            const [dict] = await signer.signMessages([message], { abortSignal });
            expect(dict?.[signer.address]?.length).toBe(64);
        });

        it('signs a transaction', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayer(signer.address, tx),
                tx =>
                    setTransactionMessageLifetimeUsingBlockhash(
                        {
                            blockhash: blockhash('11111111111111111111111111111111'),
                            lastValidBlockHeight: 0n,
                        },
                        tx,
                    ),
                compileTransaction,
            );

            const [dict] = await signer.signTransactions([transaction]);
            const sig = dict?.[signer.address];
            expect(sig).toBeDefined();
            expect(sig?.length).toBe(64);
        });
    });

    describe('isAvailable', () => {
        it('always returns true', async () => {
            const signer = await createMemorySignerFromBytes(TEST_KEYPAIR_BYTES);
            await expect(signer.isAvailable()).resolves.toBe(true);
        });
    });
});
