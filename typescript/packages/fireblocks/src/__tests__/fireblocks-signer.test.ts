import { generateKeyPairSigner } from '@solana/signers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { assertIsSolanaSigner } from '@solana/keychain-core';

import { FireblocksSigner } from '../fireblocks-signer.js';
import type { FireblocksSignerConfig } from '../types.js';
import { TEST_API_KEY, TEST_RSA_PRIVATE_KEY, TEST_VAULT_ACCOUNT_ID } from './setup.js';

// Mock fetch globally
global.fetch = vi.fn();

const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

describe('FireblocksSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('constructor', () => {
        it('creates a FireblocksSigner with valid config', () => {
            const config: FireblocksSignerConfig = {
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            };

            const signer = new FireblocksSigner(config);
            expect(signer).toBeDefined();
        });

        it('should throw error for missing apiKey', () => {
            expect(() => {
                new FireblocksSigner({
                    apiKey: '',
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                });
            }).toThrow('Missing required apiKey field');
        });

        it('should throw error for missing privateKeyPem', () => {
            expect(() => {
                new FireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: '',
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                });
            }).toThrow('Missing required privateKeyPem field');
        });

        it('should throw error for missing vaultAccountId', () => {
            expect(() => {
                new FireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: '',
                });
            }).toThrow('Missing required vaultAccountId field');
        });

        it('should validate requestDelayMs', () => {
            expect(() => {
                new FireblocksSigner({
                    apiKey: TEST_API_KEY,
                    privateKeyPem: TEST_RSA_PRIVATE_KEY,
                    vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                    requestDelayMs: -1,
                });
            }).toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                requestDelayMs: 5000,
            });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));

            warnSpy.mockRestore();
        });

        it('should use default assetId', () => {
            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(signer).toBeDefined();
        });

        it('should accept custom assetId', () => {
            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
                assetId: 'SOL_TEST',
            });

            expect(signer).toBeDefined();
        });
    });

    describe('init', () => {
        it('should initialize signer by fetching public key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

            expect(signer.address).toBe(keyPair.address);
            assertIsSolanaSigner(signer);
        });

        it('should throw error on API failure during init', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: async () => 'Unauthorized',
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await expect(signer.init()).rejects.toThrow('Fireblocks API error: 401');
        });

        it('should throw error on invalid address from API', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: 'invalid-address' }] }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await expect(signer.init()).rejects.toThrow('Invalid address from Fireblocks');
        });

        it('should not re-initialize if already initialized', async () => {
            const keyPair = await generateKeyPairSigner();

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();
            await signer.init(); // Second call should be a no-op

            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe('address', () => {
        it('should throw error if not initialized', () => {
            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            expect(() => signer.address).toThrow('Signer not initialized');
        });
    });

    describe('signMessages', () => {
        it('should throw error if not initialized', async () => {
            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Signer not initialized');
        });

        it('should sign a message successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll for completion
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

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

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

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll returning FAILED status
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'FAILED',
                }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Transaction failed with status: FAILED');
        });

        it('should throw error on invalid signature length', async () => {
            const keyPair = await generateKeyPairSigner();

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll with wrong signature length
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

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

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

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll for completion
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

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
        });

        it('should extract signature from txHash (base58) when signedMessages is absent', async () => {
            const keyPair = await generateKeyPairSigner();

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll for completion - return txHash (base58 encoded 64 bytes) instead of signedMessages
            // This tests the txHash extraction path in pollForSignature
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                    txHash: '5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW',
                }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
        });

        it('should throw error when txHash decodes to invalid length', async () => {
            const keyPair = await generateKeyPairSigner();

            // Mock init fetch
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ addresses: [{ address: keyPair.address }] }),
            });

            // Mock create transaction
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: 'tx-123', status: 'SUBMITTED' }),
            });

            // Mock poll for completion - return a short base58 string (not 64 bytes)
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    id: 'tx-123',
                    status: 'COMPLETED',
                    txHash: '2abc', // Very short, will decode to fewer than 64 bytes
                }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            await signer.init();

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            await expect(signer.signTransactions([transaction])).rejects.toThrow('Invalid txHash length');
        });
    });

    describe('isAvailable', () => {
        it('should return true when API is accessible', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ id: TEST_VAULT_ACCOUNT_ID }),
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(true);
        });

        it('should return false when API returns error', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
            });

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false when fetch throws', async () => {
            mockFetch.mockRejectedValueOnce(new Error('Network error'));

            const signer = new FireblocksSigner({
                apiKey: TEST_API_KEY,
                privateKeyPem: TEST_RSA_PRIVATE_KEY,
                vaultAccountId: TEST_VAULT_ACCOUNT_ID,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
