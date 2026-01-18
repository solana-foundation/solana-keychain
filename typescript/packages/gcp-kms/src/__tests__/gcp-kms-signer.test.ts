import { generateKeyPairSigner } from '@solana/signers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { assertIsSolanaSigner } from '@solana/keychain-core';

import { GcpKmsSigner } from '../gcp-kms-signer.js';
import type { GcpKmsSignerConfig } from '../types.js';

// Mock GCP KMS SDK
const mockAsymmetricSign = vi.fn();
const mockGetCryptoKeyVersion = vi.fn();

vi.mock('@google-cloud/kms', () => {
    return {
        v1: {
            KeyManagementServiceClient: class {
                asymmetricSign = mockAsymmetricSign;
                getCryptoKeyVersion = mockGetCryptoKeyVersion;
            },
        },
    };
});

describe('GcpKmsSigner', () => {
    const TEST_KEY_NAME = 'projects/test-project/locations/us-east1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('constructor', () => {
        it('creates a GcpKmsSigner with valid config', async () => {
            const keyPair = await generateKeyPairSigner();

            const config: GcpKmsSignerConfig = {
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            };

            const signer = new GcpKmsSigner(config);

            expect(signer.address).toBe(keyPair.address);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('should throw error for missing keyName', async () => {
            const keyPair = await generateKeyPairSigner();

            expect(() => {
                new GcpKmsSigner({
                    keyName: '',
                    publicKey: keyPair.address,
                });
            }).toThrow('Missing required keyName field');
        });

        it('should throw error for missing publicKey', () => {
            expect(() => {
                new GcpKmsSigner({
                    keyName: TEST_KEY_NAME,
                    publicKey: '',
                });
            }).toThrow('Missing required publicKey field');
        });
        it('should throw error for invalid public key', () => {
            expect(() => {
                new GcpKmsSigner({
                    keyName: TEST_KEY_NAME,
                    publicKey: 'invalid-key',
                });
            }).toThrow('Invalid Solana public key format');
        });

        it('should validate requestDelayMs', async () => {
            const keyPair = await generateKeyPairSigner();

            expect(() => {
                new GcpKmsSigner({
                    keyName: TEST_KEY_NAME,
                    publicKey: keyPair.address,
                    requestDelayMs: -1,
                });
            }).toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', async () => {
            const keyPair = await generateKeyPairSigner();
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
                requestDelayMs: 5000,
            });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));

            warnSpy.mockRestore();
        });
    });

    describe('signMessages', () => {
        it('should sign a message successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{
                signature: new Uint8Array(64).fill(0x42),
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };
            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();
            expect(mockAsymmetricSign).toHaveBeenCalledTimes(1);
            expect(mockAsymmetricSign).toHaveBeenCalledWith({
                data: message.content,
                name: TEST_KEY_NAME,
            });
        });

        it('should handle multiple messages with delay', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{
                signature: new Uint8Array(64).fill(0x42),
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
                requestDelayMs: 10,
            });

            const messages = [
                { content: new Uint8Array([1]), signatures: {} },
                { content: new Uint8Array([2]), signatures: {} },
                { content: new Uint8Array([3]), signatures: {} },
            ] as any;

            const startTime = Date.now();
            const result = await signer.signMessages(messages);
            const endTime = Date.now();

            expect(result).toHaveLength(3);
            expect(mockAsymmetricSign).toHaveBeenCalledTimes(3);
            // Should have some delay (at least 15ms for 2 delays of 10ms each)
            expect(endTime - startTime).toBeGreaterThanOrEqual(15);
        });

        it('should throw error on invalid signature length', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{
                signature: new Uint8Array(32), // Wrong length
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('Invalid signature length');
        });

        it('should throw error on missing signature', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{}]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('No signature in GCP KMS response');
        });

        it('should handle GCP KMS API errors', async () => {
            const keyPair = await generateKeyPairSigner();

            const apiError = new Error('GCP Error');
            (apiError as any).code = 403;
            mockAsymmetricSign.mockRejectedValue(apiError);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('GCP KMS Sign operation failed: GCP Error');
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{
                signature: new Uint8Array(64).fill(0x42),
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as any;

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
            expect(mockAsymmetricSign).toHaveBeenCalledTimes(1);
        });

        it('should sign multiple transactions successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockAsymmetricSign.mockResolvedValue([{
                signature: new Uint8Array(64).fill(0x42),
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const transactions = [
                { messageBytes: new Uint8Array([1]), signatures: {} },
                { messageBytes: new Uint8Array([2]), signatures: {} },
            ] as any;

            const result = await signer.signTransactions(transactions);

            expect(result).toHaveLength(2);
            expect(mockAsymmetricSign).toHaveBeenCalledTimes(2);
        });
    });

    describe('isAvailable', () => {
        it('should return true for valid Ed25519 key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockGetCryptoKeyVersion.mockResolvedValue([{
                name: TEST_KEY_NAME,
                algorithm: 'EC_SIGN_ED25519',
                state: 'ENABLED',
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(true);
        });

        it('should return false for wrong algorithm', async () => {
            const keyPair = await generateKeyPairSigner();

            mockGetCryptoKeyVersion.mockResolvedValue([{
                name: TEST_KEY_NAME,
                algorithm: 'RSA_SIGN_PKCS1_2048_SHA256',
                state: 'ENABLED',
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false for disabled key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockGetCryptoKeyVersion.mockResolvedValue([{
                name: TEST_KEY_NAME,
                algorithm: 'EC_SIGN_ED25519',
                state: 'DISABLED',
            }]);

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false on error', async () => {
            const keyPair = await generateKeyPairSigner();

            mockGetCryptoKeyVersion.mockRejectedValue(new Error('GCP error'));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
