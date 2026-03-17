import { beforeEach, describe, expect, it, vi } from 'vitest';

import { VaultSigner } from '../vault-signer.js';

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

// Mock fetch globally
global.fetch = vi.fn();

describe('VaultSigner', () => {
    const mockConfig = {
        keyName: 'test-key',
        publicKey: '11111111111111111111111111111111',
        vaultAddr: 'https://vault.example.com',
        vaultToken: 'test-token',
    };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('create', () => {
        it('should create a signer with valid configuration', () => {
            const signer = VaultSigner.create(mockConfig);
            expect(signer.address).toBe(mockConfig.publicKey);
        });

        it('should throw error for missing config fields', () => {
            expect(() => VaultSigner.create({ ...mockConfig, vaultAddr: '' })).toThrow(
                'Missing required configuration fields',
            );
        });
    });

    describe('constructor', () => {
        it('should create a signer with valid configuration', () => {
            const signer = new VaultSigner(mockConfig);
            expect(signer.address).toBe(mockConfig.publicKey);
        });

        it('should throw error for missing vaultAddr', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    vaultAddr: '',
                });
            }).toThrow('Missing required configuration fields');
        });

        it('should throw error for missing vaultToken', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    vaultToken: '',
                });
            }).toThrow('Missing required configuration fields');
        });

        it('should throw error for missing keyName', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    keyName: '',
                });
            }).toThrow('Missing required configuration fields');
        });

        it('should throw error for invalid public key', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    publicKey: 'invalid-key',
                });
            }).toThrow('Invalid Solana public key format');
        });

        it('should throw error for invalid vaultAddr URL', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    vaultAddr: 'not-a-url',
                });
            }).toThrow('vaultAddr is not a valid URL');
        });

        it('should throw error for non-HTTPS vaultAddr', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    vaultAddr: 'http://vault.example.com',
                });
            }).toThrow('vaultAddr must use HTTPS');
        });

        it('should allow localhost http vaultAddr in test environment', () => {
            const previousNodeEnv = process.env.NODE_ENV;
            try {
                process.env.NODE_ENV = 'test';

                expect(() => {
                    new VaultSigner({
                        ...mockConfig,
                        vaultAddr: 'http://127.0.0.1:8200',
                    });
                }).not.toThrow();
            } finally {
                process.env.NODE_ENV = previousNodeEnv;
            }
        });

        it('should remove trailing slash from vaultAddr', () => {
            const signer = new VaultSigner({
                ...mockConfig,
                vaultAddr: 'https://vault.example.com/',
            });
            expect(signer['vaultAddr']).toBe('https://vault.example.com');
        });

        it('should validate requestDelayMs', () => {
            expect(() => {
                new VaultSigner({
                    ...mockConfig,
                    requestDelayMs: -1,
                });
            }).toThrow('requestDelayMs must not be negative');
        });

        it('should warn for high requestDelayMs', () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            new VaultSigner({
                ...mockConfig,
                requestDelayMs: 3001,
            });
            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
            warnSpy.mockRestore();
        });
    });

    describe('isAvailable', () => {
        it('should return true when Vault key is accessible and supports signing', async () => {
            const mockResponse = {
                data: {
                    supports_signing: true,
                    type: 'ed25519',
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(true);
            expect(fetch).toHaveBeenCalledWith(
                'https://vault.example.com/v1/transit/keys/test-key',
                expect.objectContaining({
                    headers: {
                        'X-Vault-Token': 'test-token',
                    },
                    method: 'GET',
                }),
            );
        });

        it('should return false when Vault key does not support signing', async () => {
            const mockResponse = {
                data: {
                    supports_signing: false,
                    type: 'aes256-gcm96',
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when Vault key is not ed25519', async () => {
            const mockResponse = {
                data: {
                    supports_signing: true,
                    type: 'rsa-2048',
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when Vault returns error', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response('{"errors":["permission denied"]}', {
                    status: 403,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when network request fails', async () => {
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

            const signer = new VaultSigner(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });
    });

    describe('signMessages', () => {
        it('should sign a message successfully', async () => {
            const mockSignature = 'vault:v1:' + 'a'.repeat(86); // Base64 encoded signature
            const mockResponse = {
                data: {
                    signature: mockSignature,
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            const [result] = await signer.signMessages([message]);

            expect(result).toHaveProperty(mockConfig.publicKey);
            expect(fetch).toHaveBeenCalledWith(
                'https://vault.example.com/v1/transit/sign/test-key',
                expect.objectContaining({
                    body: expect.stringContaining('"input"'),
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Vault-Token': 'test-token',
                    },
                    method: 'POST',
                }),
            );
        });

        it('should handle Vault API errors', async () => {
            const mockErrorResponse = {
                errors: ['key not found'],
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockErrorResponse), {
                    status: 404,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Vault API error: key not found');
        });

        it('should handle network errors', async () => {
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network failure'));

            const signer = new VaultSigner(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Vault network request failed');
        });

        it('should handle missing signature in response', async () => {
            const mockResponse = {
                data: {},
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            await expect(signer.signMessages([message])).rejects.toThrow('Missing signature in Vault response');
        });

        it('should handle signature without vault prefix', async () => {
            const mockSignature = 'a'.repeat(86); // Base64 encoded signature without prefix
            const mockResponse = {
                data: {
                    signature: mockSignature,
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            const [result] = await signer.signMessages([message]);
            expect(result).toHaveProperty(mockConfig.publicKey);
        });

        it('should handle signature with higher vault version prefixes', async () => {
            const mockResponses = [
                { data: { signature: `vault:v2:${'a'.repeat(86)}` } },
                { data: { signature: `vault:v3:${'a'.repeat(86)}` } },
            ];

            vi.mocked(fetch)
                .mockResolvedValueOnce(
                    new Response(JSON.stringify(mockResponses[0]), {
                        status: 200,
                    }),
                )
                .mockResolvedValueOnce(
                    new Response(JSON.stringify(mockResponses[1]), {
                        status: 200,
                    }),
                );

            const signer = new VaultSigner(mockConfig);
            const messages = [
                {
                    content: new Uint8Array([1, 2, 3, 4]),
                    signatures: {},
                },
                {
                    content: new Uint8Array([5, 6, 7, 8]),
                    signatures: {},
                },
            ];

            const results = await signer.signMessages(messages);
            expect(results).toHaveLength(2);
            expect(results[0]).toHaveProperty(mockConfig.publicKey);
            expect(results[1]).toHaveProperty(mockConfig.publicKey);
        });

        it('should apply request delay for multiple messages', async () => {
            const mockSignature = 'vault:v1:' + 'a'.repeat(86);
            const mockResponse = {
                data: {
                    signature: mockSignature,
                },
            };

            vi.mocked(fetch).mockImplementation(() =>
                Promise.resolve(
                    new Response(JSON.stringify(mockResponse), {
                        status: 200,
                    }),
                ),
            );

            const delaySpy = vi.spyOn(global, 'setTimeout');
            const signer = new VaultSigner({
                ...mockConfig,
                requestDelayMs: 100,
            });

            const messages = [
                { content: new Uint8Array([1, 2, 3, 4]), signatures: {} },
                { content: new Uint8Array([5, 6, 7, 8]), signatures: {} },
                { content: new Uint8Array([9, 10, 11, 12]), signatures: {} },
            ];

            await signer.signMessages(messages);

            // First message should not have delay, subsequent ones should
            expect(delaySpy).toHaveBeenCalledTimes(2);
            expect(delaySpy).toHaveBeenNthCalledWith(1, expect.any(Function), 100);
            expect(delaySpy).toHaveBeenNthCalledWith(2, expect.any(Function), 200);

            delaySpy.mockRestore();
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully', async () => {
            const mockSignature = 'vault:v1:' + 'a'.repeat(86);
            const mockResponse = {
                data: {
                    signature: mockSignature,
                },
            };

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify(mockResponse), {
                    status: 200,
                }),
            );

            const signer = new VaultSigner(mockConfig);

            // Create a mock transaction - this is simplified
            const mockTransaction = {
                '"__transactionSize:@solana/kit"': 100,
                lifetimeConstraint: { blockhash: 'test', lastValidBlockHeight: 100n },
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as any;

            const [result] = await signer.signTransactions([mockTransaction]);

            expect(result).toHaveProperty(mockConfig.publicKey);
            expect(fetch).toHaveBeenCalledWith(
                'https://vault.example.com/v1/transit/sign/test-key',
                expect.objectContaining({
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Vault-Token': 'test-token',
                    },
                    method: 'POST',
                }),
            );
        });
    });
});
