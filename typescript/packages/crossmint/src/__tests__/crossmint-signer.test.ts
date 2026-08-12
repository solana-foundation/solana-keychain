import { createPrivateKey, createPublicKey, hkdfSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getBase16Encoder, getBase58Decoder, getBase58Encoder } from '@solana/codecs-strings';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return { ...mod, assertSignatureValid: vi.fn() };
});

vi.mock('@solana/transactions', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/transactions')>();
    return {
        ...mod,
        getBase64EncodedWireTransaction: vi.fn(() => 'AQID'),
        getTransactionDecoder: vi.fn(),
    };
});

import { assertIsSolanaSigner, assertSignatureValid } from '@solana/keychain-core';
import { isTransactionSendingSigner } from '@solana/signers';
import { getTransactionDecoder } from '@solana/transactions';
import { createCrossmintSigner } from '../crossmint-signer.js';

global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';
const mockConfig = {
    apiKey: 'cmk_test_api_key',
    apiBaseUrl: 'https://api.test.crossmint.com/api',
    walletLocator: 'userId:test-user:solana:smart',
};

const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const base16Encoder = getBase16Encoder();

const PKCS8_ED25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// Mirror of the source's deriveSignerSeed so tests can reconstruct the signing
// key and assert WHICH message bytes the submitted approval signature covers.
function deriveTestSeed(secret: string, apiKey: string): Uint8Array {
    const rawSecret = secret.startsWith('xmsk1_') ? secret.slice(6) : secret;
    const ikm = Buffer.from(base16Encoder.encode(rawSecret));
    const parts = apiKey.split('_');
    const environment = parts[1];
    const base58Data = parts.slice(2).join('_');
    const decoded = base58Encoder.encode(base58Data);
    const projectId = new TextDecoder().decode(decoded).split(':')[0];
    const info = `${projectId}:${environment}:solana-ed25519`;
    return new Uint8Array(hkdfSync('sha256', ikm, 'crossmint', info, 32));
}

function testPrivateKey(seed: Uint8Array) {
    return createPrivateKey({
        format: 'der',
        key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
        type: 'pkcs8',
    });
}
const MOCK_SIGNATURE_BYTES = new Uint8Array(64).fill(7);
const MOCK_SIGNATURE_B58 = base58Decoder.decode(MOCK_SIGNATURE_BYTES);
const MOCK_MESSAGE_BYTES = new Uint8Array([1, 2, 3]);
const MOCK_SERIALIZED_TRANSACTION_B58 = '1111';

function createMockTransaction() {
    return { messageBytes: MOCK_MESSAGE_BYTES } as any;
}

function createDecodedTransaction(overrides?: {
    messageBytes?: Uint8Array;
    signature?: Uint8Array;
    signerAddress?: string;
}) {
    return {
        messageBytes: overrides?.messageBytes ?? MOCK_MESSAGE_BYTES,
        signatures: {
            [overrides?.signerAddress ?? MOCK_ADDRESS]: overrides?.signature ?? MOCK_SIGNATURE_BYTES,
        },
    };
}

function mockWalletResponse(overrides?: Record<string, unknown>): Response {
    return new Response(
        JSON.stringify({
            address: MOCK_ADDRESS,
            chainType: 'solana',
            type: 'smart',
            ...overrides,
        }),
        { status: 200 },
    );
}

describe('CrossmintSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
        vi.mocked(assertSignatureValid).mockResolvedValue(undefined);
        vi.mocked(getTransactionDecoder).mockReturnValue({
            decode: vi.fn(() => createDecodedTransaction()),
        } as any);
    });

    describe('create', () => {
        it('creates signer from wallet locator', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await createCrossmintSigner(mockConfig);

            expect(signer.address).toBe(MOCK_ADDRESS);
            assertIsSolanaSigner(signer);
            expect(fetch).toHaveBeenCalledWith(
                'https://api.test.crossmint.com/api/2025-06-09/wallets/userId%3Atest-user%3Asolana%3Asmart',
                expect.objectContaining({
                    headers: { 'X-API-KEY': 'cmk_test_api_key' },
                    method: 'GET',
                }),
            );
        });

        it('sanitizes remote API error messages before surfacing them', async () => {
            const malicious = `evil\u0000\u0007control\nbreak ${'A'.repeat(400)}`;
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: malicious }), { status: 400 }),
            );

            let thrown: (Error & { context?: Record<string, unknown> }) | undefined;
            try {
                await createCrossmintSigner(mockConfig);
            } catch (error) {
                thrown = error as Error & { context?: Record<string, unknown> };
            }

            expect(thrown).toBeDefined();
            expect(thrown?.message).toContain('Crossmint API error: 400');
            // eslint-disable-next-line no-control-regex
            expect(thrown?.message).not.toMatch(/[\u0000-\u001f]/);
            const response = thrown?.context?.response as string;
            expect(response).toContain('evil');
            expect(response).toContain('[truncated]');
        });

        it('throws config error when apiKey is missing', async () => {
            await expect(createCrossmintSigner({ ...mockConfig, apiKey: '' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiKey'),
            });
        });

        it('throws config error when walletLocator is missing', async () => {
            await expect(createCrossmintSigner({ ...mockConfig, walletLocator: '' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('walletLocator'),
            });
        });

        it('throws config error for non-https base URL', async () => {
            await expect(
                createCrossmintSigner({ ...mockConfig, apiBaseUrl: 'http://api.crossmint.com' }),
            ).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('HTTPS'),
            });
        });

        it('throws config error for invalid base URL', async () => {
            await expect(createCrossmintSigner({ ...mockConfig, apiBaseUrl: 'not-a-url' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl is not a valid URL'),
            });
        });

        it('throws config error for non-solana wallet', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse({ chainType: 'evm' }));

            await expect(createCrossmintSigner(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('Expected Solana wallet'),
            });
        });

        it('throws config error for unsupported wallet type', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse({ type: 'custodial' }));

            await expect(createCrossmintSigner(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('Unsupported Crossmint wallet type'),
            });
        });

        it('throws config error for pollIntervalMs <= 0', async () => {
            await expect(createCrossmintSigner({ ...mockConfig, pollIntervalMs: 0 })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('pollIntervalMs'),
            });
        });

        it('throws config error for maxPollAttempts <= 0', async () => {
            await expect(createCrossmintSigner({ ...mockConfig, maxPollAttempts: 0 })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('maxPollAttempts'),
            });
        });
    });

    describe('signMessages', () => {
        it('returns not supported error', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createCrossmintSigner(mockConfig);

            const message = {
                content: new Uint8Array([1, 2, 3]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('not supported'),
            });
        });
    });

    describe('signAndSendTransactions', () => {
        it('signs via managed flow and extracts signature from txId', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'pending',
                        }),
                        { status: 201 },
                    ),
                )
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
            });

            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            const signature = results[0];

            expect(signature).toBeDefined();
            expect(signature?.length).toBe(64);
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
        });

        it('signs sequentially and stops creating transactions after a failure', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                // tx 0: create -> success
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({ id: 'tx-0', status: 'success', onChain: { txId: MOCK_SIGNATURE_B58 } }),
                        { status: 201 },
                    ),
                )
                // tx 1: create -> 500 (fails the batch)
                .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'boom' }), { status: 500 }))
                // tx 2: should NEVER be created (would only be reached under concurrent Promise.all)
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({ id: 'tx-2', status: 'success', onChain: { txId: MOCK_SIGNATURE_B58 } }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(
                signer.signAndSendTransactions([
                    createMockTransaction(),
                    createMockTransaction(),
                    createMockTransaction(),
                ]),
            ).rejects.toMatchObject({ code: 'SIGNER_REMOTE_API_ERROR' });

            // wallet create + tx0 create + tx1 create = 3 fetches; tx2 must not be created.
            expect(vi.mocked(fetch)).toHaveBeenCalledTimes(3);
        });

        it('signs via managed flow and extracts signature from serialized transaction', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-serialized',
                            status: 'success',
                            onChain: { transaction: MOCK_SERIALIZED_TRANSACTION_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            // Signature is verified against the returned transaction's message bytes
            // (Crossmint may refresh the blockhash before signing).
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
        });

        /**
         * Crossmint sponsors gas, so it is the fee payer and the message it signs
         * differs from the caller's. A signature dictionary keyed to this address
         * would assert the signature covers the caller's message, which it does not.
         */
        it('rejects signTransactions so a rewritten signature is never applied to caller bytes', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createCrossmintSigner(mockConfig);

            await expect(
                (signer as unknown as { signTransactions: (t: unknown[]) => Promise<unknown> }).signTransactions([
                    createMockTransaction(),
                ]),
            ).rejects.toMatchObject({ code: 'SIGNER_CONFIG_ERROR' });
            // Rejected locally: no transaction may be created server-side.
            expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
        });

        /**
         * Aborting stops this client from waiting; it cannot recall work Crossmint
         * has accepted, so the point is that polling ends rather than running to
         * the full attempt budget.
         */
        it('stops polling when the abort signal fires mid-flight', async () => {
            const controller = new AbortController();
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    new Response(JSON.stringify({ id: 'tx-abort', status: 'pending' }), { status: 201 }),
                )
                .mockImplementation(async () => {
                    controller.abort();
                    return new Response(JSON.stringify({ id: 'tx-abort', status: 'pending' }), { status: 200 });
                });

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 50,
                pollIntervalMs: 1,
            });

            await expect(
                signer.signAndSendTransactions([createMockTransaction()], { abortSignal: controller.signal }),
            ).rejects.toThrow();
            // Far fewer than the 50-attempt budget: wallet + create + a poll or two.
            expect(vi.mocked(fetch).mock.calls.length).toBeLessThan(6);
        });

        it('exposes a TransactionSendingSigner so Kit routes it through send, not partial signing', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createCrossmintSigner(mockConfig);

            expect(
                isTransactionSendingSigner(
                    signer as unknown as { [key: string]: unknown; address: typeof signer.address },
                ),
            ).toBe(true);
        });

        it('extracts signature from serialized transaction even when returned message bytes differ', async () => {
            const returnedMessageBytes = new Uint8Array([9, 9, 9]);
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => createDecodedTransaction({ messageBytes: returnedMessageBytes })),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-refreshed',
                            status: 'success',
                            onChain: { transaction: MOCK_SERIALIZED_TRANSACTION_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            // Verification uses the returned message bytes, not the original ones
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: returnedMessageBytes,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
        });

        it('rejects approval signatures for unrelated local transaction bytes', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-approval',
                            status: 'success',
                            approvals: {
                                submitted: [{ signature: MOCK_SIGNATURE_B58 }],
                            },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Unable to extract signature'),
            });
            expect(assertSignatureValid).not.toHaveBeenCalled();
        });

        /**
         * A smart wallet is signed by its delegated signer, not by the wallet address
         * the API reports, so the delegated address must be a verification candidate.
         */
        it('locates a signature made by the delegated signer', async () => {
            const DELEGATED_ADDRESS = 'SysvarC1ock11111111111111111111111111111111';
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => createDecodedTransaction({ signerAddress: DELEGATED_ADDRESS })),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-delegated',
                            status: 'success',
                            onChain: { transaction: MOCK_SERIALIZED_TRANSACTION_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
                signer: `server:${DELEGATED_ADDRESS}`,
            });
            const results = await signer.signAndSendTransactions([createMockTransaction()]);

            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            // Verified against the delegated signer, not the wallet address.
            expect(assertSignatureValid).toHaveBeenCalledWith(
                expect.objectContaining({ signerAddress: DELEGATED_ADDRESS }),
            );
            // The wallet address remains the signer's public identity.
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        /**
         * A wallet can be configured with both signerSecret and an explicit signer
         * locator naming a different key, e.g. the wallet's admin signer. Either may
         * be the key that actually signs, so both must be candidates.
         */
        it('treats an explicit locator signer as a candidate alongside the derived key', async () => {
            const ADMIN_ADDRESS = 'SysvarRent111111111111111111111111111111111';
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => createDecodedTransaction({ signerAddress: ADMIN_ADDRESS })),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-admin',
                            status: 'success',
                            onChain: { transaction: MOCK_SERIALIZED_TRANSACTION_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                apiKey: `sk_staging_${base58Decoder.decode(new TextEncoder().encode('proj:sig'))}`,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
                signer: `server:${ADMIN_ADDRESS}`,
                signerSecret: 'a'.repeat(64),
            });
            const results = await signer.signAndSendTransactions([createMockTransaction()]);

            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            expect(assertSignatureValid).toHaveBeenCalledWith(
                expect.objectContaining({ signerAddress: ADMIN_ADDRESS }),
            );
        });

        it('rejects when no signature can be extracted', async () => {
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => createDecodedTransaction({ signerAddress: 'other-address' })),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-no-sig',
                            status: 'success',
                            onChain: { transaction: MOCK_SERIALIZED_TRANSACTION_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Unable to extract signature'),
            });
            expect(assertSignatureValid).not.toHaveBeenCalled();
        });

        it('verifies txId when transaction decode throws', async () => {
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => {
                    throw new Error('decode failed');
                }),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-fallthrough',
                            status: 'success',
                            onChain: {
                                transaction: MOCK_SERIALIZED_TRANSACTION_B58,
                                txId: MOCK_SIGNATURE_B58,
                            },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
        });

        /**
         * When both paths fail, the embedded-transaction error is the reported cause:
         * it names which check failed, where the txId error says only that a signature
         * did not cover the caller's message, which is expected for a rewritten
         * transaction and so explains nothing.
         */
        it('reports the embedded-transaction failure when txId validation also fails', async () => {
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() => {
                    throw new Error('decode failed');
                }),
            } as any);
            vi.mocked(assertSignatureValid).mockRejectedValueOnce(new Error('signature validation failed'));
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-fallthrough-invalid',
                            status: 'success',
                            onChain: {
                                transaction: MOCK_SERIALIZED_TRANSACTION_B58,
                                txId: MOCK_SIGNATURE_B58,
                            },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toThrow('decode failed');
        });

        it('throws on failed transaction status', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'failed',
                            error: 'Insufficient funds',
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Insufficient funds'),
            });
        });

        it('throws on awaiting approval status', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'awaiting-approval',
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('awaiting approval'),
            });
        });

        it('throws timeout error when polling exceeds maxPollAttempts', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'tx-1', status: 'pending' }), { status: 201 }))
                .mockResolvedValueOnce(
                    new Response(JSON.stringify({ id: 'tx-1', status: 'pending' }), { status: 200 }),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('timed out'),
            });
        });

        it('throws on HTTP error during transaction creation', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }));

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                context: expect.objectContaining({
                    response: expect.stringContaining('Unauthorized'),
                    status: 401,
                }),
                message: expect.stringContaining('Crossmint API error: 401'),
            });
        });

        it('throws on network error during transaction creation', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockRejectedValueOnce(new Error('network down'));

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
            });
        });

        it('uses the final polled response when maxPollAttempts is 1', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'pending',
                        }),
                        { status: 201 },
                    ),
                )
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]?.length).toBe(64);
        });

        it('includes signer field in request body when configured', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-1',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner({
                ...mockConfig,
                signer: 'my-signer-id',
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await signer.signAndSendTransactions([createMockTransaction()]);

            const createCall = vi.mocked(fetch).mock.calls[1]!;
            const body = JSON.parse(createCall[1]?.body as string);
            expect(body.params.signer).toBe('my-signer-id');
        });
    });

    describe('approvals', () => {
        // Real Crossmint API key so deriveSignerSeed() succeeds:
        // {ck|sk}_{env}_{base58(projectId:nacl_signature)}.
        const SIGNER_API_KEY = `sk_staging_${base58Decoder.decode(new TextEncoder().encode('proj:sig'))}`;
        const SIGNER_SECRET = 'a'.repeat(64);
        const OUR_SIGNER = 'server:our-signer-locator';
        const OTHER_SIGNER = 'server:other-approver-locator';

        const OUR_MESSAGE_B58 = base58Decoder.decode(new Uint8Array([10, 20, 30]));
        const OTHER_MESSAGE_B58 = base58Decoder.decode(new Uint8Array([40, 50, 60]));

        function approvalConfig(overrides?: Record<string, unknown>) {
            return {
                ...mockConfig,
                apiKey: SIGNER_API_KEY,
                signer: OUR_SIGNER,
                signerSecret: SIGNER_SECRET,
                maxPollAttempts: 3,
                pollIntervalMs: 1,
                ...overrides,
            };
        }

        it('signs the pending message belonging to ITS signer locator, not pending[0]', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-multi',
                            status: 'awaiting-approval',
                            approvals: {
                                // pending[0] belongs to ANOTHER approver.
                                pending: [
                                    { signer: { locator: OTHER_SIGNER }, message: OTHER_MESSAGE_B58 },
                                    { signer: { locator: OUR_SIGNER }, message: OUR_MESSAGE_B58 },
                                ],
                            },
                        }),
                        { status: 201 },
                    ),
                )
                // approvals POST response -> success
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-multi',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner(approvalConfig());
            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);

            // The approval POST must carry OUR signer locator, and the signature
            // must be over OUR message bytes (not pending[0]'s).
            const approvalCall = vi.mocked(fetch).mock.calls[2]!;
            expect(approvalCall[0]).toContain('/transactions/tx-multi/approvals');
            const body = JSON.parse(approvalCall[1]?.body as string);
            expect(body.approvals).toHaveLength(1);
            expect(body.approvals[0].signer).toBe(OUR_SIGNER);

            // The submitted signature must be over OUR message bytes, not the
            // other approver's (pending[0]) bytes. Reconstruct the signing key
            // and verify the signature covers OUR message and NOT the other.
            const ourMessageBytes = Buffer.from(base58Encoder.encode(OUR_MESSAGE_B58));
            const otherMessageBytes = Buffer.from(base58Encoder.encode(OTHER_MESSAGE_B58));
            const sigBytes = Buffer.from(base58Encoder.encode(body.approvals[0].signature));

            const privateKey = testPrivateKey(deriveTestSeed(SIGNER_SECRET, SIGNER_API_KEY));
            const pub = createPublicKey(privateKey as unknown as Parameters<typeof createPublicKey>[0]);
            const expectedOur = Buffer.from(cryptoSign(null, ourMessageBytes, privateKey));
            expect(cryptoVerify(null, ourMessageBytes, pub, sigBytes)).toBe(true);
            expect(cryptoVerify(null, otherMessageBytes, pub, sigBytes)).toBe(false);
            expect(sigBytes.equals(expectedOur)).toBe(true);
        });

        it('drives the tx to success after a single sufficient approval (happy path)', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-happy',
                            status: 'awaiting-approval',
                            approvals: { pending: [{ signer: { locator: OUR_SIGNER }, message: OUR_MESSAGE_B58 }] },
                        }),
                        { status: 201 },
                    ),
                )
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-happy',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner(approvalConfig());
            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]?.length).toBe(64);
            // wallet + create + approvals = 3 fetches; no extra polling.
            expect(vi.mocked(fetch)).toHaveBeenCalledTimes(3);
        });

        it('does not resubmit in a loop when no pending entry is for us; errors with approvals-required', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValue(
                    new Response(
                        JSON.stringify({
                            id: 'tx-other-only',
                            status: 'awaiting-approval',
                            // Only OTHER approver pending; nothing for us.
                            approvals: { pending: [{ signer: { locator: OTHER_SIGNER }, message: OTHER_MESSAGE_B58 }] },
                        }),
                        { status: 201 },
                    ),
                );

            const signer = await createCrossmintSigner(approvalConfig({ maxPollAttempts: 5 }));

            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('additional signer approvals are required'),
            });

            // No approval POST should ever happen (nothing pending for us).
            const approvalPosts = vi.mocked(fetch).mock.calls.filter(call => String(call[0]).includes('/approvals'));
            expect(approvalPosts.length).toBe(0);
        });

        it('submits our approval at most once even when status persists as awaiting-approval', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-persist',
                            status: 'awaiting-approval',
                            approvals: { pending: [{ signer: { locator: OUR_SIGNER }, message: OUR_MESSAGE_B58 }] },
                        }),
                        { status: 201 },
                    ),
                )
                // approval POST response still awaiting-approval, and our entry
                // still appears pending (vendor lag). We must NOT resubmit.
                // Fresh Response per call: a Response body is single-read, and
                // this state is served across several polls.
                .mockImplementation(() =>
                    Promise.resolve(
                        new Response(
                            JSON.stringify({
                                id: 'tx-persist',
                                status: 'awaiting-approval',
                                approvals: {
                                    pending: [{ signer: { locator: OUR_SIGNER }, message: OUR_MESSAGE_B58 }],
                                },
                            }),
                            { status: 200 },
                        ),
                    ),
                );

            const signer = await createCrossmintSigner(approvalConfig({ maxPollAttempts: 5 }));

            // Once our approval is in, a persistent awaiting-approval status is
            // an in-flight state, not a terminal failure: the signer keeps
            // polling and surfaces its own timeout when the budget runs out.
            await expect(signer.signAndSendTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('polling timed out'),
            });

            const approvalPosts = vi.mocked(fetch).mock.calls.filter(call => String(call[0]).includes('/approvals'));
            expect(approvalPosts.length).toBe(1);
        });

        it('keeps polling when approval registers asynchronously and resolves on later success', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-async-approval',
                            status: 'awaiting-approval',
                            approvals: { pending: [{ signer: { locator: OUR_SIGNER }, message: OUR_MESSAGE_B58 }] },
                        }),
                        { status: 201 },
                    ),
                )
                // approval POST acknowledged, but Crossmint has not registered
                // it yet: status is still awaiting-approval with nothing
                // pending for us.
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-async-approval',
                            status: 'awaiting-approval',
                            approvals: { pending: [] },
                        }),
                        { status: 200 },
                    ),
                )
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            id: 'tx-async-approval',
                            status: 'success',
                            onChain: { txId: MOCK_SIGNATURE_B58 },
                        }),
                        { status: 200 },
                    ),
                );

            const signer = await createCrossmintSigner(approvalConfig());
            const results = await signer.signAndSendTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]?.length).toBe(64);

            const approvalPosts = vi.mocked(fetch).mock.calls.filter(call => String(call[0]).includes('/approvals'));
            expect(approvalPosts.length).toBe(1);
            // wallet + create + approvals + final poll = 4 fetches.
            expect(vi.mocked(fetch)).toHaveBeenCalledTimes(4);
        });
    });

    describe('isAvailable', () => {
        it('returns true when wallet fetch succeeds', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockResolvedValueOnce(mockWalletResponse()); // isAvailable()

            const signer = await createCrossmintSigner(mockConfig);
            const available = await signer.isAvailable();
            expect(available).toBe(true);
        });

        it('returns false when wallet fetch fails', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create()
                .mockRejectedValueOnce(new Error('network down')); // isAvailable()

            const signer = await createCrossmintSigner(mockConfig);
            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });
    });
});
