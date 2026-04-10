import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { getBase58Decoder } from '@solana/codecs-strings';

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
import { getTransactionDecoder } from '@solana/transactions';
import { createCrossmintSigner } from '../crossmint-signer.js';

global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';
const mockConfig = {
    apiKey: 'cmk_test_api_key',
    apiBaseUrl: 'https://api.test.crossmint.com/api',
    walletLocator: 'userId:test-user:solana:smart',
};
const MOCK_DERIVED_ADDRESS = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const ORIGINAL_TEST_DERIVED_PUBKEY = process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY;

const base58Decoder = getBase58Decoder();
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
        delete process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY;
        vi.mocked(assertSignatureValid).mockResolvedValue(undefined);
        vi.mocked(getTransactionDecoder).mockReturnValue({
            decode: vi.fn(() => createDecodedTransaction()),
        } as any);
    });

    afterAll(() => {
        if (ORIGINAL_TEST_DERIVED_PUBKEY == null) {
            delete process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY;
            return;
        }
        process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY = ORIGINAL_TEST_DERIVED_PUBKEY;
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

        it('uses TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY in test runtime when set', async () => {
            process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY = MOCK_DERIVED_ADDRESS;
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await createCrossmintSigner(mockConfig);

            expect(signer.address).toBe(MOCK_DERIVED_ADDRESS);
        });

        it('throws config error for invalid TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY', async () => {
            process.env.TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY = 'not-a-solana-address';
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            await expect(createCrossmintSigner(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY'),
            });
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
                message: expect.stringContaining('Invalid apiBaseUrl'),
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

    describe('signTransactions', () => {
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

            const results = await signer.signTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            const signature = results[0]![signer.address];

            expect(signature).toBeDefined();
            expect(signature?.length).toBe(64);
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
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

            const results = await signer.signTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]![signer.address]).toEqual(MOCK_SIGNATURE_BYTES);
            // Signature is verified against the returned transaction's message bytes
            // (Crossmint may refresh the blockhash before signing).
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
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

            const results = await signer.signTransactions([createMockTransaction()]);
            expect(results[0]![signer.address]).toEqual(MOCK_SIGNATURE_BYTES);
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Unable to extract signature'),
            });
            expect(assertSignatureValid).not.toHaveBeenCalled();
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
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

            const results = await signer.signTransactions([createMockTransaction()]);
            expect(results[0]![signer.address]).toEqual(MOCK_SIGNATURE_BYTES);
            expect(assertSignatureValid).toHaveBeenCalledWith({
                data: MOCK_MESSAGE_BYTES,
                signature: MOCK_SIGNATURE_BYTES,
                signerAddress: signer.address,
            });
        });

        it('rejects txId when transaction decode throws and txId validation fails', async () => {
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toThrow(
                'signature validation failed',
            );
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Unauthorized'),
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

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
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

            const results = await signer.signTransactions([createMockTransaction()]);
            expect(results).toHaveLength(1);
            expect(results[0]![signer.address]?.length).toBe(64);
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

            await signer.signTransactions([createMockTransaction()]);

            const createCall = vi.mocked(fetch).mock.calls[1]!;
            const body = JSON.parse(createCall[1]?.body as string);
            expect(body.params.signer).toBe('my-signer-id');
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
