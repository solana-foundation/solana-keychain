import { address } from '@solana/addresses';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { assertIsSolanaSigner } from '@solana/keychain-core';

import { GcpKmsSigner } from '../gcp-kms-signer.js';
import type { GcpKmsSignerConfig } from '../types.js';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        assertSignatureValid: vi.fn(),
        sanitizeRemoteErrorResponse:
            mod.sanitizeRemoteErrorResponse ??
            ((text: string) =>
                text
                    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .slice(0, 256)),
    };
});

const mockGetRequestHeaders = vi.fn();
const mockFetch = vi.fn();
const originalFetch = globalThis.fetch;

vi.mock('google-auth-library', () => {
    return {
        GoogleAuth: class {
            getRequestHeaders = mockGetRequestHeaders;
        },
    };
});

function createJsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    });
}

function getFetchCall(index: number): [string, RequestInit] {
    return mockFetch.mock.calls[index] as [string, RequestInit];
}

function assertAuthorizedRequest(url: string, method: string, callIndex = 0): RequestInit {
    const [calledUrl, init] = getFetchCall(callIndex);
    expect(calledUrl).toBe(url);
    expect(init.method).toBe(method);

    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer test-token');
    return init;
}

describe('GcpKmsSigner', () => {
    const TEST_KEY_NAME =
        'projects/test-project/locations/us-east1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1';
    const TEST_PUBLIC_KEY = address('11111111111111111111111111111111');
    const SIGN_ENDPOINT = `https://cloudkms.googleapis.com/v1/${TEST_KEY_NAME}:asymmetricSign`;
    const PUBLIC_KEY_ENDPOINT = `https://cloudkms.googleapis.com/v1/${TEST_KEY_NAME}/publicKey`;
    const TEST_SIGNATURE_BYTES = new Uint8Array(64).fill(0x42);
    const TEST_SIGNATURE_BASE64 = Buffer.from(TEST_SIGNATURE_BYTES).toString('base64');

    beforeAll(() => {
        globalThis.fetch = mockFetch as unknown as typeof fetch;
    });

    beforeEach(() => {
        vi.clearAllMocks();

        mockGetRequestHeaders.mockResolvedValue(new Headers({ authorization: 'Bearer test-token' }));
    });

    afterAll(() => {
        globalThis.fetch = originalFetch;
    });

    describe('create', () => {
        it('creates a GcpKmsSigner with valid config', () => {
            const signer = GcpKmsSigner.create({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            expect(signer.address).toBe(TEST_PUBLIC_KEY);
            assertIsSolanaSigner(signer);
        });

        it('should throw error for missing keyName', () => {
            expect(() => {
                GcpKmsSigner.create({
                    keyName: '',
                    publicKey: TEST_PUBLIC_KEY,
                });
            }).toThrow('Missing required keyName field');
        });
    });

    describe('constructor', () => {
        it('creates a GcpKmsSigner with valid config', () => {
            const config: GcpKmsSignerConfig = {
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            };

            const signer = new GcpKmsSigner(config);

            expect(signer.address).toBe(TEST_PUBLIC_KEY);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('should throw error for missing keyName', () => {
            expect(() => {
                new GcpKmsSigner({
                    keyName: '',
                    publicKey: TEST_PUBLIC_KEY,
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

        it('should validate requestDelayMs', () => {
            expect(() => {
                new GcpKmsSigner({
                    keyName: TEST_KEY_NAME,
                    publicKey: TEST_PUBLIC_KEY,
                    requestDelayMs: -1,
                });
            }).toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
                requestDelayMs: 5000,
            });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));

            warnSpy.mockRestore();
        });
    });

    describe('signMessages', () => {
        it('should sign a message successfully', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({ signature: TEST_SIGNATURE_BASE64 }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };
            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();
            expect(mockGetRequestHeaders).toHaveBeenCalledWith(SIGN_ENDPOINT);
            expect(mockFetch).toHaveBeenCalledTimes(1);

            const init = assertAuthorizedRequest(SIGN_ENDPOINT, 'POST');
            const headers = new Headers(init.headers);
            expect(headers.get('content-type')).toBe('application/json');
            expect(init.body).toBe(
                JSON.stringify({
                    data: Buffer.from(message.content).toString('base64'),
                }),
            );
        });

        it('should handle multiple messages with delay', async () => {
            mockFetch.mockImplementation(() =>
                Promise.resolve(createJsonResponse({ signature: TEST_SIGNATURE_BASE64 })),
            );

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
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
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(endTime - startTime).toBeGreaterThanOrEqual(15);
        });

        it('should throw error on invalid signature length', async () => {
            const shortSignature = Buffer.from(new Uint8Array(32).fill(0x42)).toString('base64');
            mockFetch.mockResolvedValue(createJsonResponse({ signature: shortSignature }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('Invalid signature length');
        });

        it('should throw error on missing signature', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({}));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('No signature in GCP KMS response');
        });

        it('should handle GCP KMS API errors', async () => {
            mockFetch.mockResolvedValue(
                createJsonResponse(
                    {
                        error: {
                            message: 'GCP Error',
                        },
                    },
                    403,
                ),
            );

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('GCP KMS API error: 403');
        });

        it('should handle network errors', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('GCP KMS network request failed');
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({ signature: TEST_SIGNATURE_BASE64 }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const transaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as any;

            const result = await signer.signTransactions([transaction]);

            expect(result).toHaveLength(1);
            expect(result[0]).toHaveProperty(signer.address);
            expect(mockFetch).toHaveBeenCalledTimes(1);

            assertAuthorizedRequest(SIGN_ENDPOINT, 'POST');
        });

        it('should sign multiple transactions successfully', async () => {
            mockFetch.mockImplementation(() =>
                Promise.resolve(createJsonResponse({ signature: TEST_SIGNATURE_BASE64 })),
            );

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const transactions = [
                { messageBytes: new Uint8Array([1]), signatures: {} },
                { messageBytes: new Uint8Array([2]), signatures: {} },
            ] as any;

            const result = await signer.signTransactions(transactions);

            expect(result).toHaveLength(2);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it('should throw error on invalid signature length', async () => {
            const shortSignature = Buffer.from(new Uint8Array(32).fill(0x42)).toString('base64');
            mockFetch.mockResolvedValue(createJsonResponse({ signature: shortSignature }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const transaction = { messageBytes: new Uint8Array([1, 2, 3, 4]), signatures: {} } as any;

            await expect(signer.signTransactions([transaction])).rejects.toThrow('Invalid signature length');
        });

        it('should throw error on missing signature', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({}));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const transaction = { messageBytes: new Uint8Array([1, 2, 3, 4]), signatures: {} } as any;

            await expect(signer.signTransactions([transaction])).rejects.toThrow('No signature in GCP KMS response');
        });

        it('should handle GCP KMS API errors', async () => {
            mockFetch.mockResolvedValue(
                createJsonResponse(
                    {
                        error: {
                            message: 'GCP Error',
                        },
                    },
                    403,
                ),
            );

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const transaction = { messageBytes: new Uint8Array([1, 2, 3, 4]), signatures: {} } as any;

            await expect(signer.signTransactions([transaction])).rejects.toThrow('GCP KMS API error: 403');
        });
    });

    describe('isAvailable', () => {
        it('should return true for valid Ed25519 key', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({ algorithm: 'EC_SIGN_ED25519' }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(true);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            assertAuthorizedRequest(PUBLIC_KEY_ENDPOINT, 'GET');
        });

        it('should return false for wrong algorithm', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({ algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false for missing public key response', async () => {
            mockFetch.mockResolvedValue(createJsonResponse({}));

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('should return false on API error', async () => {
            mockFetch.mockResolvedValue(
                createJsonResponse(
                    {
                        error: {
                            message: 'Forbidden',
                        },
                    },
                    403,
                ),
            );

            const signer = new GcpKmsSigner({
                keyName: TEST_KEY_NAME,
                publicKey: TEST_PUBLIC_KEY,
            });

            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
