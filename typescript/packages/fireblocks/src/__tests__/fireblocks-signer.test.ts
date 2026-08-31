import { getBase58Decoder, getUtf8Encoder } from '@solana/codecs-strings';
import {
    address,
    appendTransactionMessageInstruction,
    blockhash,
    compileTransaction,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { generateKeyPairSigner } from '@solana/signers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
    assertIsSolanaTransactionSigner,
    assertSignatureValid,
    idempotencyKeyFromMessage,
    SignerError,
    SignerErrorCode,
} from '@solana/keychain-core';

import { createFireblocksSigner } from '../fireblocks-signer.js';
import { TEST_API_KEY, TEST_RSA_PRIVATE_KEY, TEST_VAULT_ACCOUNT_ID } from './setup.js';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        assertSignatureValid: vi.fn(),
        sanitizeRemoteErrorResponse:
            mod.sanitizeRemoteErrorResponse ??
            ((text: string) =>
                `${text
                    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .slice(0, 256)} [truncated]`),
    };
});

global.fetch = vi.fn();

const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

describe('createFireblocksSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('config validation', () => {
        it('should throw error for missing apiKey', async () => {
            await expect(
                createFireblocksSigner({
                    apiKey: '',
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('Missing required apiKey field');
        });

        it('should throw error for missing privateKeyPem', async () => {
            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: '',
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('Missing required privateKeyPem field');
        });

        it('should throw error for missing vaultAccountId', async () => {
            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: '',
                }),
            ).rejects.toThrow('Missing required vaultAccountId field');
        });

        it('should throw error when apiBaseUrl is not a valid URL', async () => {
            await expect(
                createFireblocksSigner({
                    apiBaseUrl: 'not-a-url',
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('apiBaseUrl is not a valid URL');
        });

        it('should throw error when apiBaseUrl does not use HTTPS', async () => {
            await expect(
                createFireblocksSigner({
                    apiBaseUrl: 'http://api.fireblocks.test',
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('apiBaseUrl must use HTTPS');
        });

        it('should validate requestDelayMs', async () => {
            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                    requestDelayMs: -1,
                }),
            ).rejects.toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', async () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                requestDelayMs: 5000,
            });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));

            warnSpy.mockRestore();
        });

        it('should throw INVALID_PRIVATE_KEY for an unparseable PEM before any network call', async () => {
            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: 'not-a-pem',
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_INVALID_PRIVATE_KEY',
                message: expect.stringContaining('Failed to parse Fireblocks RSA private key'),
            });

            expect(mockFetch).not.toHaveBeenCalled();
        });
    });

    describe('initialization', () => {
        it('creates and initializes a signer by fetching the public key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer.address).toBe(keyPair.address);
            assertIsSolanaTransactionSigner(signer);
        });

        it('accepts a custom assetId', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address, assetId: 'SOL_TEST' }] }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                assetId: 'SOL_TEST',
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer.address).toBe(keyPair.address);
        });

        it('accepts useProgramCall:true', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                useProgramCall: true,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer).toBeDefined();
        });

        it('should throw error on API failure during initialization', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: async () => 'Unauthorized',
            });

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('Fireblocks API error: 401');
        });

        it('should throw HTTP_ERROR when fetch fails during initialization', async () => {
            mockFetch.mockRejectedValueOnce(new Error('Network timeout'));

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Fireblocks network request failed'),
            });
        });

        it('should throw error on invalid address from API', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: 'invalid-address' }] }),
            });

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toThrow('Invalid address from Fireblocks');
        });

        it('should throw structured error on malformed address response shape', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({}),
            });

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_INVALID_PUBLIC_KEY',
                message: expect.stringContaining('returned no address'),
            });
        });

        it('selects the address for the configured asset', async () => {
            const wanted = await generateKeyPairSigner();
            const other = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    addresses: [
                        { address: other.address, assetId: 'SOL_TEST' },
                        { address: wanted.address, assetId: 'SOL' },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer.address).toBe(wanted.address);
        });

        it('selects the address for a custom assetId, not the default', async () => {
            const devnet = await generateKeyPairSigner();
            const mainnet = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    addresses: [
                        { address: mainnet.address, assetId: 'SOL' },
                        { address: devnet.address, assetId: 'SOL_TEST' },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                assetId: 'SOL_TEST',
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer.address).toBe(devnet.address);
        });

        it('rejects an ambiguous address response', async () => {
            const first = await generateKeyPairSigner();
            const second = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    addresses: [
                        { address: first.address, assetId: 'SOL' },
                        { address: second.address, assetId: 'SOL' },
                    ],
                }),
            });

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_INVALID_PUBLIC_KEY',
                message: expect.stringContaining('cannot choose a signing identity'),
            });
        });

        it('rejects a response with no address for the configured asset', async () => {
            const other = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: other.address, assetId: 'SOL_TEST' }] }),
            });

            await expect(
                createFireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_INVALID_PUBLIC_KEY',
                message: expect.stringContaining('returned no address'),
            });
        });

        it('accepts duplicate entries for the same address', async () => {
            const wanted = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    addresses: [
                        { address: wanted.address, assetId: 'SOL' },
                        { address: wanted.address, assetId: 'SOL' },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer.address).toBe(wanted.address);
        });
    });

    describe('signMessages', () => {
        it('should throw HTTP_ERROR when fetch fails during signing request', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            mockFetch.mockRejectedValueOnce(new Error('Network timeout'));

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Fireblocks network request failed'),
            });
        });

        it('should sign a message successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                    signedMessages: [
                        {
                            signature: {
                                fullSig: '42'.repeat(64), // 64 bytes as hex
                            },
                        },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };
            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();
        });

        it('should throw error on transaction failure', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'FAILED',
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Transaction failed with status: FAILED');
        });

        it('should throw error on invalid signature length', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                    signedMessages: [
                        {
                            signature: {
                                fullSig: '42'.repeat(32), // 32 bytes instead of 64
                            },
                        },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Invalid signature length');
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully with RAW signing', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                    signedMessages: [
                        {
                            signature: {
                                fullSig: '42'.repeat(64),
                            },
                        },
                    ],
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
        });

        it('should throw when COMPLETED response has no signedMessages', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            await expect(signer.signTransactions([transaction])).rejects.toThrow(
                'No signature found in response (no signedMessages)',
            );
        });
    });

    describe('signTransactions with PROGRAM_CALL', () => {
        async function createProgramCallSigner(): Promise<{
            signer: Awaited<ReturnType<typeof createFireblocksSigner>>;
            transaction: Parameters<Awaited<ReturnType<typeof createFireblocksSigner>>['signTransactions']>[0][0];
        }> {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                useProgramCall: true,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const transaction = compileTransaction(
                pipe(
                    createTransactionMessage({ version: 0 }),
                    tx => setTransactionMessageFeePayer(keyPair.address, tx),
                    tx =>
                        setTransactionMessageLifetimeUsingBlockhash(
                            { blockhash: blockhash('11111111111111111111111111111111'), lastValidBlockHeight: 100n },
                            tx,
                        ),
                    tx =>
                        appendTransactionMessageInstruction(
                            { programAddress: address('11111111111111111111111111111111') },
                            tx,
                        ),
                ),
            ) as Parameters<Awaited<ReturnType<typeof createFireblocksSigner>>['signTransactions']>[0][0];

            return { signer, transaction };
        }

        function mockCreateAndPoll(pollBody: Record<string, unknown>): void {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-789', status: 'SUBMITTED' }),
            });
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => pollBody,
            });
        }

        it('requests sign-only PROGRAM_CALL for the serialized transaction and returns the signature', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockCreateAndPoll({
                id: 'tx-789',
                signedMessages: [{ signature: { fullSig: '42'.repeat(64) } }],
                status: 'SIGNED',
            });

            const result = await signer.signTransactions([transaction]);

            const createBody = JSON.parse(mockFetch.mock.calls[1]![1].body as string);
            expect(createBody).toMatchObject({
                extraParameters: {
                    programCallData: getBase64EncodedWireTransaction(transaction),
                    signOnly: true,
                    useDurableNonce: false,
                },
                operation: 'PROGRAM_CALL',
            });
            expect(result[0]).toHaveProperty(signer.address);
        });

        it('carries a message-derived externalTxId on the create', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockCreateAndPoll({
                id: 'tx-789',
                signedMessages: [{ signature: { fullSig: '42'.repeat(64) } }],
                status: 'SIGNED',
            });

            await signer.signTransactions([transaction]);

            const namespace = getUtf8Encoder().encode(`fireblocks:solana:program_call:SOL:${TEST_VAULT_ACCOUNT_ID}:`);
            const messageBytes = new Uint8Array(transaction.messageBytes);
            const namespaced = new Uint8Array(namespace.length + messageBytes.length);
            namespaced.set(namespace);
            namespaced.set(messageBytes, namespace.length);
            const createBody = JSON.parse(mockFetch.mock.calls[1]![1].body as string);
            expect(createBody.externalTxId).toBe(await idempotencyKeyFromMessage(namespaced));
        });

        it('accepts the signature carried as txHash', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            const signatureBytes = new Uint8Array(64).fill(7);
            mockCreateAndPoll({
                id: 'tx-789',
                status: 'SIGNED',
                txHash: getBase58Decoder().decode(signatureBytes),
            });

            const result = await signer.signTransactions([transaction]);

            expect(result[0]![signer.address]).toEqual(signatureBytes);
        });

        it('verifies the returned signature against the local message bytes', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            const signatureBytes = new Uint8Array(64).fill(7);
            mockCreateAndPoll({
                id: 'tx-789',
                status: 'SIGNED',
                txHash: getBase58Decoder().decode(signatureBytes),
            });

            await signer.signTransactions([transaction]);

            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: transaction.messageBytes,
                signature: signatureBytes,
                signerAddress: signer.address,
            });
        });

        it('reports a broadcast made despite signOnly as BROADCAST_UNCONFIRMED', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockCreateAndPoll({
                id: 'tx-789',
                status: 'BROADCASTING',
                txHash: getBase58Decoder().decode(new Uint8Array(64).fill(7)),
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
            });
        });

        it('keeps the transaction id when the poll itself fails', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-789', status: 'SUBMITTED' }),
            });
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 503,
                text: async () => 'upstream unavailable',
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
                context: { providerTransactionId: 'tx-789' },
            });
        });

        it('keeps the transaction id when the attempt budget runs out', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });
            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                useProgramCall: true,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });
            const { transaction } = await createProgramCallSigner();
            mockFetch.mockImplementation(() =>
                Promise.resolve({ json: async () => ({ id: 'tx-789', status: 'SUBMITTED' }), ok: true }),
            );

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
                context: { providerTransactionId: 'tx-789' },
            });
        });

        it('reports a 5xx create as BROADCAST_UNCONFIRMED', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 503,
                text: async () => 'upstream unavailable',
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
            });
        });

        it('treats a status-bearing caller abort during create as unconfirmed', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            const controller = new AbortController();
            const reason = new SignerError(SignerErrorCode.REMOTE_API_ERROR, { status: 400 });
            mockFetch.mockImplementationOnce(async (_input, init) => {
                controller.abort(reason);
                expect(init?.signal?.aborted).toBe(true);
                throw new Error('aborted');
            });

            const error = await signer.signTransactions([transaction], { abortSignal: controller.signal }).then(
                () => {
                    throw new Error('expected the create failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );

            const createBody = JSON.parse(mockFetch.mock.calls[1]![1].body as string);
            expect(error.code).toBe(SignerErrorCode.BROADCAST_UNCONFIRMED);
            expect(error.context?.cause).toBe(reason);
            expect(error.context?.status).toBeUndefined();
            expect(error.context?.idempotencyKey).toBe(createBody.externalTxId);
        });

        it('keeps a transaction id named in a failed create body', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 503,
                text: async () => JSON.stringify({ id: 'tx-accepted' }),
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
                context: { providerTransactionId: 'tx-accepted' },
            });
        });

        it('keeps a 4xx create a plain rejection', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 400,
                text: async () => 'bad request',
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
            });
        });

        it('reports an accepted create with no transaction id as BROADCAST_UNCONFIRMED', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ status: 'SUBMITTED' }),
            });

            await expect(signer.signTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
            });
        });

        it('stops a PROGRAM_CALL batch at the first failure and reports what completed', async () => {
            const { signer, transaction } = await createProgramCallSigner();
            mockCreateAndPoll({
                id: 'tx-789',
                signedMessages: [{ signature: { fullSig: '42'.repeat(64) } }],
                status: 'SIGNED',
            });
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 503,
                text: async () => 'unavailable',
            });

            const error = await signer.signTransactions([transaction, transaction, transaction]).then(
                () => {
                    throw new Error('expected the failing create to reject');
                },
                (thrown: SignerError) => thrown,
            );

            expect(error.code).toBe('SIGNER_BROADCAST_UNCONFIRMED');
            expect(error.context?.failedIndex).toBe(1);
            expect(error.context?.completedSignatures).toHaveLength(1);
            expect(mockFetch.mock.calls).toHaveLength(4);
        });

        it('rejects a v1 message before any PROGRAM_CALL is created', async () => {
            const { signer } = await createProgramCallSigner();
            const v1Transaction = {
                messageBytes: new Uint8Array([0x81, 1, 2, 3]),
                signatures: {},
            } as unknown as Parameters<Awaited<ReturnType<typeof createFireblocksSigner>>['signTransactions']>[0][0];

            await expect(signer.signTransactions([v1Transaction])).rejects.toThrow(/legacy and v0 messages only/);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe('isAvailable', () => {
        it('should return true when API is accessible', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });
            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: TEST_VAULT_ACCOUNT_ID }),
            });

            const available = await signer.isAvailable();

            expect(available).toBe(true);
        });

        it('should return false when API returns error', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });
            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: async () => 'Unauthorized',
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false when fetch throws', async () => {
            const keyPair = await generateKeyPairSigner();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });
            const signer = await createFireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            mockFetch.mockRejectedValueOnce(new Error('Network error'));

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
