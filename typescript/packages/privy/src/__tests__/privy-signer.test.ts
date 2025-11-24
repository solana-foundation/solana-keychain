import { generateKeyPair, signBytes } from '@solana/keys';
import { createSignableMessage, createSignerFromKeyPair, generateKeyPairSigner } from '@solana/signers';
import {
    Base64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';
import { assertIsSolanaSigner } from '@solana-keychain/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PrivySigner } from '../privy-signer.js';

global.fetch = vi.fn();

const MOCK_B64_WIRE_TX =
    'Af1fCRSrZ9ASprap8D3ZLPsbzeCs6uihvj/jfjm3UrAY72by5zKMRd7YAIbJCl9gyRHQbw+xdklET2ZNmZi3iA2AAQABAurnRuGN5bfL2osZZMdGlvL1qz8k0GbdLhiP1fICgkmsBUpTWpkpIQZNJOhxYNo4fHw1td28kruB5B+oQEEFRI1NhzEgE0w/YfwaeZi2Ns/mLoZvq2Sx5NVQg7Am7wrjGwEBAAxIZWxsbywgUHJpdnkA' as Base64EncodedWireTransaction;

vi.mock('@solana/transactions', async () => {
    const actual = await vi.importActual<typeof import('@solana/transactions')>('@solana/transactions');
    return {
        ...actual,
        getBase64EncodedWireTransaction: vi.fn(() => MOCK_B64_WIRE_TX),
    };
});

const createMockTransaction = (): Transaction & TransactionWithinSizeLimit & TransactionWithLifetime => {
    return {} as Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;
};

describe('PrivySigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });
    const mockConfig = {
        apiBaseUrl: 'https://api.privy.test',
        appId: 'test-app-id',
        appSecret: 'test-app-secret',
        walletId: 'test-wallet-id',
    };

    const setupMockWalletResponse = (address: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    address,
                    chain_type: 'solana',
                    id: mockConfig.walletId,
                }),
            ok: true,
            status: 200,
        });
    };

    const setupMockSignMessageResponse = (signatureBase64: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    data: {
                        encoding: 'base64',
                        signature: signatureBase64,
                    },
                    method: 'signMessage',
                }),
            ok: true,
            status: 200,
        });
    };

    describe('create', () => {
        it('creates and initializes a PrivySigner', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            expect(signer.address).toBeTruthy();
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
            expect(typeof signer.address).toBe('string');
            assertIsSolanaSigner(signer);
        });

        it('sets address field correctly from API response', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            expect(signer.address).toBe(keyPair.address);
        });

        it('throws error on API failure', async () => {
            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: () => Promise.resolve('Unauthorized'),
            });

            await expect(PrivySigner.create(mockConfig)).rejects.toThrow();
        });

        it('throws error on invalid public key', async () => {
            setupMockWalletResponse('not-a-valid-address');

            await expect(PrivySigner.create(mockConfig)).rejects.toThrow();
        });

        describe('config validation', () => {
            it('throws CONFIG_ERROR when appId is missing', async () => {
                const invalidConfig = { ...mockConfig, appId: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when appSecret is missing', async () => {
                const invalidConfig = { ...mockConfig, appSecret: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when walletId is missing', async () => {
                const invalidConfig = { ...mockConfig, walletId: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });
        });

        describe('network errors', () => {
            it('throws HTTP_ERROR when fetch fails during create', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_HTTP_ERROR',
                    message: expect.stringContaining('Privy network request failed'),
                });
            });
        });

        describe('parsing errors', () => {
            it('throws PARSING_ERROR when response is invalid JSON', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                    json: () => Promise.reject(new Error('Invalid JSON')),
                    ok: true,
                    status: 200,
                });

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_PARSING_ERROR',
                    message: expect.stringContaining('Failed to parse Privy response'),
                });
            });
        });

        describe('response validation', () => {
            it('throws REMOTE_API_ERROR when address is missing from response', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                    json: () =>
                        Promise.resolve({
                            chain_type: 'solana',
                            id: mockConfig.walletId,
                            // missing address field
                        }),
                    ok: true,
                    status: 200,
                });

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_REMOTE_API_ERROR',
                    message: expect.stringContaining('Missing address in Privy wallet response'),
                });
            });
        });
    });

    describe('signMessages', () => {
        it('signs a message via Privy API', async () => {
            const keyPair = await generateKeyPair();
            const keyPaierSigner = await createSignerFromKeyPair(keyPair);
            const address = keyPaierSigner.address;

            setupMockWalletResponse(address);

            const signer = await PrivySigner.create(mockConfig);

            const messageContent = new Uint8Array([1, 2, 3, 4]);
            const signature = await signBytes(keyPair.privateKey, messageContent);

            const signatureBase64 = Buffer.from(signature).toString('base64');
            setupMockSignMessageResponse(signatureBase64);

            const message = createSignableMessage(messageContent);
            const [sigDict] = await signer.signMessages([message]);
            expect(sigDict).toBeTruthy();
            expect(sigDict?.[signer.address]).toBeTruthy();
        });

        it('throws HTTP_ERROR when fetch fails during signing', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Privy network request failed'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Privy signing response'),
            });
        });

        it('throws REMOTE_API_ERROR when signature is missing from response', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        data: {
                            encoding: 'base64',
                            // missing signature field
                        },
                        method: 'signMessage',
                    }),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signature in Privy response'),
            });
        });
    });

    describe('signTransactions', () => {
        it('handles API errors during transaction signing', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve('Internal server error'),
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        it('throws HTTP_ERROR when fetch fails during transaction signing', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Privy network request failed'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Privy signing response'),
            });
        });

        it('throws REMOTE_API_ERROR when signed_transaction is missing from response', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        data: {
                            encoding: 'base64',
                            // missing signed_transaction field
                        },
                        method: 'signTransaction',
                    }),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signed_transaction in Privy response'),
            });
        });
    });

    describe('isAvailable', () => {
        it('returns true when API is reachable', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);
            setupMockWalletResponse(keyPair.address);
            const available = await signer.isAvailable();
            expect(available).toBe(true);
        });

        it('returns false when API is unreachable', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);
            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve('Server error'),
            });
            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });
    });
});
