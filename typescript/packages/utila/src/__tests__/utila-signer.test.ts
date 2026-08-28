import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeJwt, decodeProtectedHeader, importPKCS8, SignJWT } from 'jose';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        extractAndVerifyReturnedSignature: vi.fn(
            async ({
                returnedTransactionBytes,
                signerAddress,
            }: Parameters<typeof mod.extractAndVerifyReturnedSignature>[0]) =>
                mod.extractSignatureFromTransactionBytes({
                    signerAddress,
                    transactionBytes: returnedTransactionBytes,
                })[signerAddress],
        ),
    };
});

vi.mock('@solana/transactions', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/transactions')>();
    return {
        ...mod,
        getBase64EncodedWireTransaction: vi.fn(() => 'AQID'),
        getTransactionDecoder: vi.fn(),
    };
});

import { assertIsSolanaTransactionSigner, extractAndVerifyReturnedSignature } from '@solana/keychain-core';
import { getTransactionDecoder } from '@solana/transactions';
import { createUtilaAccessToken, createUtilaSigner } from '../utila-signer.js';
import { TEST_EMAIL, TEST_RSA_PRIVATE_KEY } from './setup.js';

global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';
const MOCK_MESSAGE_BYTES = new Uint8Array([1, 2, 3]);
const MOCK_SIGNATURE_BYTES = new Uint8Array(64).fill(7);
const MOCK_RAW_TRANSACTION = 'AQIDBA==';

const mockConfig = {
    apiBaseUrl: 'https://api.test.utila.io',
    network: 'networks/solana-devnet',
    serviceAccountEmail: TEST_EMAIL,
    serviceAccountPrivateKeyPem: TEST_RSA_PRIVATE_KEY,
    vaultId: 'vault-test',
    walletId: 'wallet-test',
};

function createMockTransaction(messageBytes = MOCK_MESSAGE_BYTES) {
    return { messageBytes } as any;
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
            wallet: {
                solanaDetails: {
                    address: MOCK_ADDRESS,
                },
                ...overrides,
            },
        }),
        { status: 200 },
    );
}

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status });
}

function fetchCall(index: number): [string, RequestInit] {
    return vi.mocked(fetch).mock.calls[index] as [string, RequestInit];
}

describe('UtilaSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
        vi.mocked(getTransactionDecoder).mockReturnValue({
            decode: vi.fn(() => createDecodedTransaction()),
        } as any);
    });

    describe('createUtilaAccessToken', () => {
        it('creates an RS256 JWT with Utila service account claims', async () => {
            const privateKey = await importPKCS8(TEST_RSA_PRIVATE_KEY, 'RS256');
            const token = await createUtilaAccessToken(TEST_EMAIL, privateKey);
            const header = decodeProtectedHeader(token);
            const payload = decodeJwt(token);

            expect(header.alg).toBe('RS256');
            expect(payload.sub).toBe(TEST_EMAIL);
            expect(payload.aud).toBe('https://api.utila.io/');
            expect(typeof payload.exp).toBe('number');
            expect(token).not.toContain('BEGIN PRIVATE KEY');
        });
    });

    describe('create', () => {
        it('rejects a wallet resource naming another vault', async () => {
            await expect(
                createUtilaSigner({
                    ...mockConfig,
                    vaultId: 'vaults/vault-test',
                    walletId: 'vaults/other-vault/wallets/wallet-test',
                }),
            ).rejects.toMatchObject({ code: 'SIGNER_CONFIG_ERROR' });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('creates signer from an existing Utila wallet', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await createUtilaSigner(mockConfig);

            expect(signer.address).toBe(MOCK_ADDRESS);
            assertIsSolanaTransactionSigner(signer);
            expect(fetch).toHaveBeenCalledWith(
                'https://api.test.utila.io/v2/vaults/vault-test/wallets/wallet-test',
                expect.objectContaining({
                    headers: expect.objectContaining({
                        Authorization: expect.stringMatching(/^Bearer /),
                    }),
                    method: 'GET',
                }),
            );
        });

        it('throws config error when required fields are missing', async () => {
            await expect(createUtilaSigner({ ...mockConfig, serviceAccountEmail: '' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('serviceAccountEmail'),
            });
        });

        it('throws config error for non-https base URL', async () => {
            await expect(createUtilaSigner({ ...mockConfig, apiBaseUrl: 'http://api.utila.io' })).rejects.toMatchObject(
                {
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('HTTPS'),
                },
            );
        });

        it('throws config error for invalid base URL', async () => {
            await expect(createUtilaSigner({ ...mockConfig, apiBaseUrl: 'not-a-url' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl is not a valid URL'),
            });
        });

        it('throws config error when requestDelayMs is negative', async () => {
            await expect(createUtilaSigner({ ...mockConfig, requestDelayMs: -1 })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('requestDelayMs must not be negative'),
            });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('warns when requestDelayMs is greater than 3000ms', async () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            await createUtilaSigner({ ...mockConfig, requestDelayMs: 5000 });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
        });

        it('throws invalid public key when wallet response omits Solana address', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(jsonResponse({ wallet: {} }));

            await expect(createUtilaSigner(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_INVALID_PUBLIC_KEY',
            });
        });

        it('accepts a PEM with escaped newlines', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await createUtilaSigner({
                ...mockConfig,
                serviceAccountPrivateKeyPem: TEST_RSA_PRIVATE_KEY.replace(/\n/g, '\\n'),
            });

            expect(signer.address).toBe(MOCK_ADDRESS);
        });
    });

    describe('signTransactions', () => {
        it('initiates Utila signing with publish disabled and extracts signed transaction signature', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'AWAITING_SIGNATURE',
                        },
                    }),
                )
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            solanaTransaction: {
                                rawTransaction: MOCK_RAW_TRANSACTION,
                            },
                            state: 'SIGNED',
                        },
                    }),
                );

            const signer = await createUtilaSigner({
                ...mockConfig,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
            });
            const results = await signer.signTransactions([createMockTransaction()]);

            expect(results).toHaveLength(1);
            expect(results[0]![signer.address]).toEqual(MOCK_SIGNATURE_BYTES);
            expect(extractAndVerifyReturnedSignature).toHaveBeenCalledWith(
                expect.objectContaining({
                    originalMessageBytes: MOCK_MESSAGE_BYTES,
                    signerAddress: signer.address,
                }),
            );

            const [url, init] = fetchCall(1);
            expect(url).toBe('https://api.test.utila.io/v2/vaults/vault-test/transactions:initiate');
            const body = JSON.parse(init.body as string);
            expect(body).toMatchObject({
                designatedSigners: [`users/${TEST_EMAIL}`],
                details: {
                    solanaSerializedTransaction: {
                        network: 'networks/solana-devnet',
                        publish: false,
                        rawTransaction: 'AQID',
                        replaceBlockhash: false,
                        tryReplaceBlockhash: false,
                    },
                },
            });

            expect(fetchCall(2)[0]).toBe('https://api.test.utila.io/v2/vaults/vault-test/transactions/tx-1?view=FULL');
        });

        it('signs when the signer instance is frozen, as @solana/signers freezes fee-payer signers', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'AWAITING_SIGNATURE',
                        },
                    }),
                )
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            solanaTransaction: {
                                rawTransaction: MOCK_RAW_TRANSACTION,
                            },
                            state: 'SIGNED',
                        },
                    }),
                );

            const signer = await createUtilaSigner({
                ...mockConfig,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
            });
            Object.freeze(signer);
            const results = await signer.signTransactions([createMockTransaction()]);

            expect(results).toHaveLength(1);
            expect(results[0]![signer.address]).toEqual(MOCK_SIGNATURE_BYTES);
        });

        it('throws on terminal Utila state', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'FAILED',
                        },
                    }),
                );

            const signer = await createUtilaSigner({ ...mockConfig, pollIntervalMs: 1 });
            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('FAILED'),
            });
        });

        it('throws when polling times out', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'AWAITING_SIGNATURE',
                        },
                    }),
                )
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'AWAITING_SIGNATURE',
                        },
                    }),
                );

            const signer = await createUtilaSigner({
                ...mockConfig,
                maxPollAttempts: 1,
                pollIntervalMs: 1,
            });

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('timed out'),
            });
        });

        it('throws when signed response is missing raw transaction', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            state: 'SIGNED',
                        },
                    }),
                );

            const signer = await createUtilaSigner(mockConfig);
            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('rawTransaction'),
            });
        });

        it('throws when the signed transaction has no signature for the signer address', async () => {
            vi.mocked(getTransactionDecoder).mockReturnValue({
                decode: vi.fn(() =>
                    createDecodedTransaction({ signerAddress: 'So11111111111111111111111111111111111111112' }),
                ),
            } as any);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse())
                .mockResolvedValueOnce(
                    jsonResponse({
                        transaction: {
                            name: 'vaults/vault-test/transactions/tx-1',
                            solanaTransaction: {
                                rawTransaction: MOCK_RAW_TRANSACTION,
                            },
                            state: 'SIGNED',
                        },
                    }),
                );

            const signer = await createUtilaSigner(mockConfig);
            await expect(signer.signTransactions([createMockTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('No signature found'),
            });
        });
    });

    describe('access token caching', () => {
        function signedTransactionResponse(): Response {
            return jsonResponse({
                transaction: {
                    name: 'vaults/vault-test/transactions/tx-1',
                    solanaTransaction: {
                        rawTransaction: MOCK_RAW_TRANSACTION,
                    },
                    state: 'SIGNED',
                },
            });
        }

        afterEach(() => {
            vi.useRealTimers();
        });

        it('reuses the cached access token across consecutive requests', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createUtilaSigner(mockConfig);

            const signSpy = vi.spyOn(SignJWT.prototype, 'sign');
            signSpy.mockClear();
            vi.mocked(fetch)
                .mockResolvedValueOnce(signedTransactionResponse())
                .mockResolvedValueOnce(signedTransactionResponse());

            await signer.signTransactions([createMockTransaction()]);
            await signer.signTransactions([createMockTransaction()]);

            expect(signSpy).toHaveBeenCalledTimes(1);
        });

        it('shares one mint between concurrent requests', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createUtilaSigner(mockConfig);

            const signSpy = vi.spyOn(SignJWT.prototype, 'sign');
            signSpy.mockClear();
            vi.mocked(fetch)
                .mockResolvedValueOnce(signedTransactionResponse())
                .mockResolvedValueOnce(signedTransactionResponse());

            await Promise.all([
                signer.signTransactions([createMockTransaction()]),
                signer.signTransactions([createMockTransaction()]),
            ]);

            expect(signSpy).toHaveBeenCalledTimes(1);
        });

        it('retries the mint after a failed mint', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createUtilaSigner(mockConfig);

            const signSpy = vi.spyOn(SignJWT.prototype, 'sign').mockRejectedValueOnce(new Error('crypto unavailable'));
            signSpy.mockClear();
            vi.mocked(fetch).mockResolvedValueOnce(signedTransactionResponse());

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toThrow();
            await expect(signer.signTransactions([createMockTransaction()])).resolves.toBeDefined();
            expect(signSpy).toHaveBeenCalledTimes(2);
        });

        it('re-mints the access token when the cached token is near expiry', async () => {
            vi.useFakeTimers();
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createUtilaSigner(mockConfig);

            const signSpy = vi.spyOn(SignJWT.prototype, 'sign');
            signSpy.mockClear();
            vi.mocked(fetch)
                .mockResolvedValueOnce(signedTransactionResponse())
                .mockResolvedValueOnce(signedTransactionResponse());

            await signer.signTransactions([createMockTransaction()]);
            expect(signSpy).toHaveBeenCalledTimes(1);

            vi.setSystemTime(Date.now() + 55 * 60 * 1000);
            await signer.signTransactions([createMockTransaction()]);
            expect(signSpy).toHaveBeenCalledTimes(2);
        });
    });

    describe('isAvailable', () => {
        it('returns true when wallet fetch succeeds and false when it fails', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse()).mockResolvedValueOnce(mockWalletResponse());
            const signer = await createUtilaSigner(mockConfig);

            await expect(signer.isAvailable()).resolves.toBe(true);

            vi.mocked(fetch).mockRejectedValueOnce(new Error('network'));
            await expect(signer.isAvailable()).resolves.toBe(false);
        });
    });
});
