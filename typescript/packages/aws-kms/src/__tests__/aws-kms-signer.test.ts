import { generateKeyPairSigner } from '@solana/signers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { assertIsSolanaSigner } from '@solana-keychain/core';

import { AwsKmsSigner } from '../aws-kms-signer.js';
import type { AwsKmsSignerConfig } from '../types.js';

// Mock AWS SDK
const mockSend = vi.fn();

vi.mock('@aws-sdk/client-kms', () => {
    // Create proper constructor mock classes
    class MockKMSClient {
        send = mockSend;
    }

    class MockSignCommand {
        input: unknown;
        constructor(params: unknown) {
            this.input = params;
        }
    }

    class MockDescribeKeyCommand {
        input: unknown;
        constructor(params: unknown) {
            this.input = params;
        }
    }

    return {
        KMSClient: MockKMSClient,
        SignCommand: MockSignCommand,
        DescribeKeyCommand: MockDescribeKeyCommand,
        MessageType: {
            RAW: 'RAW',
            DIGEST: 'DIGEST',
        },
        SigningAlgorithmSpec: {
            ED25519_SHA_512: 'ED25519_SHA_512',
            ED25519_PH_SHA_512: 'ED25519_PH_SHA_512',
        },
    };
});

describe('AwsKmsSigner', () => {
    const TEST_KEY_ID = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('constructor', () => {
        it('creates an AwsKmsSigner with valid config', async () => {
            const keyPair = await generateKeyPairSigner();

            const config: AwsKmsSignerConfig = {
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            };

            const signer = new AwsKmsSigner(config);

            expect(signer.address).toBe(keyPair.address);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('sets address field correctly from config', async () => {
            const keyPair = await generateKeyPairSigner();

            const config: AwsKmsSignerConfig = {
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            };

            const signer = new AwsKmsSigner(config);
            expect(signer.address).toBe(keyPair.address);
        });

        it('should throw error for missing keyId', async () => {
            const keyPair = await generateKeyPairSigner();

            expect(() => {
                new AwsKmsSigner({
                    keyId: '',
                    publicKey: keyPair.address,
                });
            }).toThrow('Missing required keyId field');
        });

        it('should throw error for missing publicKey', () => {
            expect(() => {
                new AwsKmsSigner({
                    keyId: TEST_KEY_ID,
                    publicKey: '',
                });
            }).toThrow('Missing required publicKey field');
        });

        it('should throw error for invalid public key', () => {
            expect(() => {
                new AwsKmsSigner({
                    keyId: TEST_KEY_ID,
                    publicKey: 'invalid-key',
                });
            }).toThrow('Invalid Solana public key format');
        });

        it('should validate requestDelayMs', async () => {
            const keyPair = await generateKeyPairSigner();

            expect(() => {
                new AwsKmsSigner({
                    keyId: TEST_KEY_ID,
                    publicKey: keyPair.address,
                    requestDelayMs: -1,
                });
            }).toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', async () => {
            const keyPair = await generateKeyPairSigner();
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
                requestDelayMs: 5000,
            });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));

            warnSpy.mockRestore();
        });

        it('should accept region configuration', async () => {
            const keyPair = await generateKeyPairSigner();

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
                region: 'us-west-2',
            });

            expect(signer).toBeDefined();
        });

        it('should accept credentials configuration', async () => {
            const keyPair = await generateKeyPairSigner();

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
                credentials: {
                    accessKeyId: 'test-access-key',
                    secretAccessKey: 'test-secret-key',
                },
            });

            expect(signer).toBeDefined();
        });

        it('should accept session token in credentials', async () => {
            const keyPair = await generateKeyPairSigner();

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
                credentials: {
                    accessKeyId: 'test-access-key',
                    secretAccessKey: 'test-secret-key',
                    sessionToken: 'test-session-token',
                },
            });

            expect(signer).toBeDefined();
        });
    });

    describe('signMessages', () => {
        it('should sign a message successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                Signature: new Uint8Array(64).fill(0x42),
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            // Provide required 'signatures' property to satisfy the type
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };
            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();
            expect(mockSend).toHaveBeenCalledTimes(1);
        });

        it('should handle multiple messages with delay', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                Signature: new Uint8Array(64).fill(0x42),
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
                requestDelayMs: 10,
            });

            const messages = [
                { content: new Uint8Array([1]) },
                { content: new Uint8Array([2]) },
                { content: new Uint8Array([3]) },
            ];

            // Add missing 'signatures' property for each message to satisfy the type requirement
            const messagesWithSignatures = messages.map(msg => ({
                ...msg,
                signatures: {},
            }));

            const startTime = Date.now();
            const result = await signer.signMessages(messagesWithSignatures);
            const endTime = Date.now();

            expect(result).toHaveLength(3);
            expect(mockSend).toHaveBeenCalledTimes(3);
            // Should have some delay (at least 15ms for 2 delays of 10ms each)
            expect(endTime - startTime).toBeGreaterThanOrEqual(15);
        });

        it('should throw error on invalid signature length', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                Signature: new Uint8Array(32), // Wrong length
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('Invalid signature length');
        });

        it('should throw error on missing signature', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                Signature: undefined,
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('No signature in AWS KMS response');
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                Signature: new Uint8Array(64).fill(0x42),
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as unknown as Parameters<typeof signer.signTransactions>[0][0];

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
            expect(mockSend).toHaveBeenCalledTimes(1);
        });
    });

    describe('isAvailable', () => {
        it('should return true for valid Ed25519 key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                KeyMetadata: {
                    KeyId: TEST_KEY_ID,
                    KeySpec: 'ECC_NIST_EDWARDS25519',
                    KeyUsage: 'SIGN_VERIFY',
                    KeyState: 'Enabled',
                },
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(true);
        });

        it('should return false for wrong key spec', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                KeyMetadata: {
                    KeyId: TEST_KEY_ID,
                    KeySpec: 'RSA_2048',
                    KeyUsage: 'SIGN_VERIFY',
                    KeyState: 'Enabled',
                },
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false for wrong key usage', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                KeyMetadata: {
                    KeyId: TEST_KEY_ID,
                    KeySpec: 'ECC_NIST_EDWARDS25519',
                    KeyUsage: 'ENCRYPT_DECRYPT',
                    KeyState: 'Enabled',
                },
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false for disabled key', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                KeyMetadata: {
                    KeyId: TEST_KEY_ID,
                    KeySpec: 'ECC_NIST_EDWARDS25519',
                    KeyUsage: 'SIGN_VERIFY',
                    KeyState: 'Disabled',
                },
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false on error', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockRejectedValue(new Error('AWS error'));

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false on missing metadata', async () => {
            const keyPair = await generateKeyPairSigner();

            mockSend.mockResolvedValue({
                KeyMetadata: undefined,
            });

            const signer = new AwsKmsSigner({
                keyId: TEST_KEY_ID,
                publicKey: keyPair.address,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
