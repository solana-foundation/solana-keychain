import { generateKeyPair, signBytes } from '@solana/keys';
import { createSignableMessage, createSignerFromKeyPair, generateKeyPairSigner } from '@solana/signers';
import {
    Base64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';
import { assertIsSolanaSigner } from '@solana/keychain-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TurnkeySigner } from '../turnkey-signer.js';

global.fetch = vi.fn();

const MOCK_B64_WIRE_TX =
    'Af1fCRSrZ9ASprap8D3ZLPsbzeCs6uihvj/jfjm3UrAY72by5zKMRd7YAIbJCl9gyRHQbw+xdklET2ZNmZi3iA2AAQABAurnRuGN5bfL2osZZMdGlvL1qz8k0GbdLhiP1fICgkmsBUpTWpkpIQZNJOhxYNo4fHw1td28kruB5B+oQEEFRI1NhzEgE0w/YfwaeZi2Ns/mLoZvq2Sx5NVQg7Am7wrjGwEBAAxIZWxsbywgUHJpdnkA' as Base64EncodedWireTransaction;

// Mock the transaction encoding function
vi.mock('@solana/transactions', async () => {
    const actual = await vi.importActual<typeof import('@solana/transactions')>('@solana/transactions');
    return {
        ...actual,
        getBase64EncodedWireTransaction: vi.fn(() => MOCK_B64_WIRE_TX),
    };
});

// Helper to create a mock transaction without needing real transaction building
const createMockTransaction = (): Transaction & TransactionWithinSizeLimit & TransactionWithLifetime => {
    return {} as Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;
};

describe('TurnkeySigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    // Mock P256 key pair for API authentication (not the Solana Ed25519 keys)
    // Using compressed format (33 bytes) as required by Turnkey API
    const mockConfig = {
        apiBaseUrl: 'https://api.turnkey.test',
        apiPrivateKey: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
        apiPublicKey: '02c3b87ed8c58e8c2e6ae8cb10e5b47fa08b2fc1f48aaca48e2ef16e8ec5a1e0c0',
        organizationId: 'test-org-id',
        privateKeyId: 'test-private-key-id',
        publicKey: '', // Will be filled in by tests
    };

    const setupMockSignResponse = (r: string, s: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    activity: {
                        result: {
                            signRawPayloadResult: {
                                r,
                                s,
                            },
                        },
                        status: 'COMPLETED',
                    },
                }),
            ok: true,
            status: 200,
        });
    };

    const setupMockWhoAmIResponse = (organizationId: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    organizationId,
                    organizationName: 'Test Organization',
                    userId: 'test-user-id',
                    username: 'test@example.com',
                }),
            ok: true,
            status: 200,
        });
    };

    describe('constructor', () => {
        it('creates a TurnkeySigner with valid config', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            expect(signer.address).toBe(keyPair.address);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('sets address field correctly from config', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            expect(signer.address).toBe(keyPair.address);
        });

        describe('config validation', () => {
            it('throws CONFIG_ERROR when apiPublicKey is missing', async () => {
                const keyPair = await generateKeyPairSigner();
                const invalidConfig = { ...mockConfig, apiPublicKey: '', publicKey: keyPair.address };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });

            it('throws CONFIG_ERROR when apiPrivateKey is missing', async () => {
                const keyPair = await generateKeyPairSigner();
                const invalidConfig = { ...mockConfig, apiPrivateKey: '', publicKey: keyPair.address };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });

            it('throws CONFIG_ERROR when organizationId is missing', async () => {
                const keyPair = await generateKeyPairSigner();
                const invalidConfig = { ...mockConfig, organizationId: '', publicKey: keyPair.address };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });

            it('throws CONFIG_ERROR when privateKeyId is missing', async () => {
                const keyPair = await generateKeyPairSigner();
                const invalidConfig = { ...mockConfig, privateKeyId: '', publicKey: keyPair.address };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });

            it('throws CONFIG_ERROR when publicKey is missing', () => {
                const invalidConfig = { ...mockConfig, publicKey: '' };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });

            it('throws CONFIG_ERROR when publicKey is invalid', () => {
                const invalidConfig = { ...mockConfig, publicKey: 'not-a-valid-address' };

                expect(() => new TurnkeySigner(invalidConfig)).toThrow();
            });
        });
    });

    describe('signMessages', () => {
        it('signs a message via Turnkey API', async () => {
            const keyPair = await generateKeyPair();
            const keyPairSigner = await createSignerFromKeyPair(keyPair);

            const config = {
                ...mockConfig,
                publicKey: keyPairSigner.address,
            };

            const signer = new TurnkeySigner(config);

            const messageContent = new Uint8Array([1, 2, 3, 4]);
            const signature = await signBytes(keyPair.privateKey, messageContent);

            // Split signature into r and s (32 bytes each)
            const r = Buffer.from(signature.slice(0, 32)).toString('hex');
            const s = Buffer.from(signature.slice(32, 64)).toString('hex');

            setupMockSignResponse(r, s);

            const message = createSignableMessage(messageContent);
            const [sigDict] = await signer.signMessages([message]);

            expect(sigDict).toBeTruthy();
            expect(sigDict?.[signer.address]).toBeTruthy();
        });

        it('handles undersized signature components by padding', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            // Create undersized components (less than 32 bytes)
            const r = '1234abcd'; // 4 bytes
            const s = '5678ef90'; // 4 bytes

            setupMockSignResponse(r, s);

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            const [sigDict] = await signer.signMessages([message]);

            expect(sigDict).toBeTruthy();
            expect(sigDict?.[signer.address]).toBeTruthy();

            // Signature should be 64 bytes (r and s padded to 32 each)
            const signatureBytes = sigDict?.[signer.address];
            expect(signatureBytes?.length).toBe(64);
        });

        it('throws SIGNING_FAILED when r component is oversized', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            // Create oversized r component (> 32 bytes)
            const r = Buffer.alloc(33, 0xff).toString('hex');
            const s = Buffer.alloc(32, 0x01).toString('hex');

            setupMockSignResponse(r, s);

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Invalid signature component length'),
            });
        });

        it('throws SIGNING_FAILED when s component is oversized', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            // Create oversized s component (> 32 bytes)
            const r = Buffer.alloc(32, 0x01).toString('hex');
            const s = Buffer.alloc(33, 0xff).toString('hex');

            setupMockSignResponse(r, s);

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
                message: expect.stringContaining('Invalid signature component length'),
            });
        });

        it('throws HTTP_ERROR when fetch fails during signing', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Turnkey network request failed'),
            });
        });

        it('throws REMOTE_API_ERROR on 401 Unauthorized', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: () => Promise.resolve('Unauthorized'),
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Turnkey API error: 401'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Turnkey response'),
            });
        });

        it('throws REMOTE_API_ERROR when signature components are missing', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        activity: {
                            result: {
                                // Missing signRawPayloadResult
                            },
                            status: 'COMPLETED',
                        },
                    }),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signature components'),
            });
        });
    });

    describe('signTransactions', () => {
        it('handles API errors during transaction signing', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

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

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Turnkey network request failed'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Turnkey response'),
            });
        });

        it('throws REMOTE_API_ERROR when signedTransaction is missing from response', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        activity: {
                            result: {},
                            status: 'COMPLETED',
                        },
                    }),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signedTransaction'),
            });
        });
    });

    describe('isAvailable', () => {
        it('returns true when API is reachable and org matches', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            setupMockWhoAmIResponse(mockConfig.organizationId);

            const available = await signer.isAvailable();
            expect(available).toBe(true);
        });

        it('returns false when API returns 401', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: () => Promise.resolve('Unauthorized'),
            });

            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });

        it('returns false when API is unreachable', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network error'));

            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });

        it('returns false when organization ID does not match', async () => {
            const keyPair = await generateKeyPairSigner();

            const config = {
                ...mockConfig,
                publicKey: keyPair.address,
            };

            const signer = new TurnkeySigner(config);

            setupMockWhoAmIResponse('different-org-id');

            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });
    });
});
