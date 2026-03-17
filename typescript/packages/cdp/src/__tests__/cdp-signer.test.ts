import * as nodeCrypto from 'node:crypto';

import { Address } from '@solana/addresses';
import { assertIsSolanaSigner } from '@solana/keychain-core';
import { generateKeyPairSigner } from '@solana/signers';
import {
    type Base64EncodedWireTransaction,
    type Transaction,
    type TransactionWithinSizeLimit,
    type TransactionWithLifetime,
} from '@solana/transactions';
import { beforeEach, describe, expect, it, vi } from 'vitest';

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

import { CdpSigner } from '../cdp-signer.js';
import type { CdpSignerConfig } from '../types.js';

// --- Valid test credentials ---

// Generate a real Ed25519 keypair so that createKeyPairFromBytes seed↔pubkey validation passes.
// Ed25519 PKCS#8 DER: 16-byte header + 32-byte seed
// Ed25519 SPKI DER:   12-byte header + 32-byte public key
function generateTestApiKeySecret(): string {
    const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const seed = pkcs8.subarray(16, 48);
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const pubKeyBytes = spki.subarray(12, 44);
    return Buffer.concat([seed, pubKeyBytes]).toString('base64');
}

const TEST_CDP_API_KEY_SECRET = generateTestApiKeySecret();

// P-256 PKCS#8 DER (67 bytes)
const TEST_CDP_WALLET_SECRET = Buffer.from([
    // outer SEQUENCE (65 bytes)
    0x30, 0x41,
    // version INTEGER 0
    0x02, 0x01, 0x00,
    // AlgorithmIdentifier SEQUENCE (19 bytes)
    0x30, 0x13,
    // OID ecPublicKey (1.2.840.10045.2.1)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    // OID prime256v1 (1.2.840.10045.3.1.7)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    // privateKey OCTET STRING (39 bytes)
    0x04, 0x27,
    // ECPrivateKey SEQUENCE (37 bytes)
    0x30, 0x25,
    // version INTEGER 1
    0x02, 0x01, 0x01,
    // privateKey OCTET STRING (32 bytes) — scalar 0x01...01 is in [1, n-1] for P-256
    0x04, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
]).toString('base64');

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock wire transaction (same real-structure tx used across keychain tests)
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

// A valid base58 Solana address for tests
const TEST_ADDRESS = '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV';

function makeConfig(overrides?: Partial<CdpSignerConfig>): CdpSignerConfig {
    return {
        cdpApiKeyId: 'test-api-key-name',
        cdpApiKeySecret: TEST_CDP_API_KEY_SECRET,
        cdpWalletSecret: TEST_CDP_WALLET_SECRET,
        address: TEST_ADDRESS,
        ...overrides,
    };
}

describe('CdpSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('create()', () => {
        it('creates a CdpSigner with valid config', async () => {
            const signer = await CdpSigner.create(makeConfig());

            expect(signer.address).toBe(TEST_ADDRESS);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('throws CONFIG_ERROR for missing cdpApiKeyId', async () => {
            await expect(CdpSigner.create(makeConfig({ cdpApiKeyId: '' }))).rejects.toThrow(
                'Missing required cdpApiKeyId field',
            );
        });

        it('throws CONFIG_ERROR for missing cdpApiKeySecret', async () => {
            await expect(CdpSigner.create(makeConfig({ cdpApiKeySecret: '' }))).rejects.toThrow(
                'Missing required cdpApiKeySecret field',
            );
        });

        it('throws CONFIG_ERROR for missing cdpWalletSecret', async () => {
            await expect(CdpSigner.create(makeConfig({ cdpWalletSecret: '' }))).rejects.toThrow(
                'Missing required cdpWalletSecret field',
            );
        });

        it('throws CONFIG_ERROR for missing address', async () => {
            await expect(CdpSigner.create(makeConfig({ address: '' }))).rejects.toThrow(
                'Missing required address field',
            );
        });

        it('throws CONFIG_ERROR for invalid address', async () => {
            await expect(CdpSigner.create(makeConfig({ address: 'not-a-valid-address' }))).rejects.toThrow(
                'Invalid Solana address format',
            );
        });

        it('throws CONFIG_ERROR for negative requestDelayMs', async () => {
            await expect(CdpSigner.create(makeConfig({ requestDelayMs: -1 }))).rejects.toThrow(
                'requestDelayMs must not be negative',
            );
        });

        it('warns for high requestDelayMs', async () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            await CdpSigner.create(makeConfig({ requestDelayMs: 5000 }));
            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
            warnSpy.mockRestore();
        });

        it('accepts custom baseUrl', async () => {
            const signer = await CdpSigner.create(makeConfig({ baseUrl: 'https://custom.example.com' }));
            expect(signer).toBeDefined();
        });

        it('throws CONFIG_ERROR when baseUrl is not a valid URL', async () => {
            await expect(CdpSigner.create(makeConfig({ baseUrl: 'not-a-url' }))).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('baseUrl is not a valid URL'),
            });
        });

        it('throws CONFIG_ERROR when baseUrl does not use HTTPS', async () => {
            await expect(
                CdpSigner.create(makeConfig({ baseUrl: 'http://api.cdp.coinbase.com' })),
            ).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('baseUrl must use HTTPS'),
            });
        });

        it('accepts requestDelayMs of 0', async () => {
            const signer = await CdpSigner.create(makeConfig({ requestDelayMs: 0 }));
            expect(signer).toBeDefined();
        });

        it('throws CONFIG_ERROR when Ed25519 pubkey does not match seed', async () => {
            // 64 bytes where seed and pubkey are mismatched (all 0x42)
            const mismatchedKey = Buffer.alloc(64, 0x42).toString('base64');
            await expect(CdpSigner.create(makeConfig({ cdpApiKeySecret: mismatchedKey }))).rejects.toThrow(
                'Invalid cdpApiKeySecret',
            );
        });
    });

    describe('signMessages', () => {
        it('signs a message and returns a signature dictionary', async () => {
            // Base58-encoded 64-byte signature
            const base58Sig = '5LfnqEfGPFBaHHeQBiNkgQ2EPy4FkVLKE7cjMYc7gv6EjE8Vs5gqaXcZHjpxr3yj5TMt7j3JdJPkXfnwXxXiNAh';
            mockFetch.mockResolvedValue(new Response(JSON.stringify({ signature: base58Sig }), { status: 200 }));

            const signer = await CdpSigner.create(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };
            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[TEST_ADDRESS as Address]).toBeDefined();
            expect(mockFetch).toHaveBeenCalledTimes(1);
            const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
            expect(url).toContain('/sign/message');
            expect(JSON.parse(init.body as string)).toMatchObject({ message: 'hello' });
        });

        it('handles multiple messages with requestDelayMs', async () => {
            const base58Sig = '5LfnqEfGPFBaHHeQBiNkgQ2EPy4FkVLKE7cjMYc7gv6EjE8Vs5gqaXcZHjpxr3yj5TMt7j3JdJPkXfnwXxXiNAh';
            // Use mockImplementation so each concurrent call gets a fresh Response (body can only be read once)
            mockFetch.mockImplementation(() =>
                Promise.resolve(new Response(JSON.stringify({ signature: base58Sig }), { status: 200 })),
            );

            const signer = await CdpSigner.create(makeConfig({ requestDelayMs: 10 }));
            const messages = [
                { content: new TextEncoder().encode('one'), signatures: {} },
                { content: new TextEncoder().encode('two'), signatures: {} },
            ];

            const startTime = Date.now();
            const result = await signer.signMessages(messages);
            const elapsed = Date.now() - startTime;

            expect(result).toHaveLength(2);
            expect(elapsed).toBeGreaterThanOrEqual(8); // at least one 10ms delay
        });

        it('throws HTTP_ERROR on network failure', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const signer = await CdpSigner.create(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('CDP signMessage network request failed');
        });

        it('throws REMOTE_API_ERROR on non-2xx response', async () => {
            mockFetch.mockResolvedValue(new Response('{"error":"Unauthorized"}', { status: 401 }));

            const signer = await CdpSigner.create(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('CDP signMessage API error: 401');
        });

        it('throws SIGNING_FAILED for invalid signature length', async () => {
            // Return a base58 string that decodes to != 64 bytes (small value)
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ signature: '1' }), { status: 200 }), // '1' decodes to 1 byte
            );

            const signer = await CdpSigner.create(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow('Invalid signature length');
        });

        it('throws SERIALIZATION_ERROR for invalid UTF-8 message', async () => {
            const signer = await CdpSigner.create(makeConfig());
            const message = { content: new Uint8Array([0xff]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow(
                'CDP signMessage requires a valid UTF-8 message',
            );
        });
    });

    describe('signTransactions', () => {
        it('accepts a key pair address as the signer address', async () => {
            const keyPair = await generateKeyPairSigner();
            const signer = await CdpSigner.create(makeConfig({ address: keyPair.address }));
            expect(signer.address).toBe(keyPair.address);
        });

        it('calls CDP signTransaction with the correct address and wire transaction', async () => {
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ signedTransaction: MOCK_B64_WIRE_TX }), { status: 200 }),
            );

            const signer = await CdpSigner.create(makeConfig());
            const mockTx = createMockTransaction();

            // The CDP call succeeds; extractSignatureFromWireTransaction throws because
            // MOCK_B64_WIRE_TX was not signed by TEST_ADDRESS (integration tests cover success path)
            await expect(signer.signTransactions([mockTx])).rejects.toThrow();

            expect(mockFetch).toHaveBeenCalledTimes(1);
            const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
            expect(url).toContain('/sign/transaction');
            expect(JSON.parse(init.body as string)).toMatchObject({ transaction: MOCK_B64_WIRE_TX });
        });

        it('throws HTTP_ERROR on network failure', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const signer = await CdpSigner.create(makeConfig());
            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow(
                'CDP signTransaction network request failed',
            );
        });

        it('throws REMOTE_API_ERROR on non-2xx response', async () => {
            mockFetch.mockResolvedValue(new Response('{"error":"Forbidden"}', { status: 403 }));

            const signer = await CdpSigner.create(makeConfig());
            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow('CDP signTransaction API error: 403');
        });
    });

    describe('isAvailable', () => {
        it('returns true when the account is accessible', async () => {
            mockFetch.mockResolvedValue(new Response(JSON.stringify({ address: TEST_ADDRESS }), { status: 200 }));

            const signer = await CdpSigner.create(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(true);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
            expect(url).toContain(TEST_ADDRESS);
        });

        it('returns false when the account is not found', async () => {
            mockFetch.mockResolvedValue(new Response('', { status: 404 }));

            const signer = await CdpSigner.create(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('returns false when the CDP API is unreachable', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const signer = await CdpSigner.create(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('returns false on 401 unauthorized', async () => {
            mockFetch.mockResolvedValue(new Response('', { status: 401 }));

            const signer = await CdpSigner.create(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('returns false when auth header generation fails', async () => {
            const signer = await CdpSigner.create(makeConfig());
            const subtleSignSpy = vi
                .spyOn(globalThis.crypto.subtle, 'sign')
                .mockRejectedValueOnce(new Error('sign failed'));

            const available = await signer.isAvailable();

            expect(available).toBe(false);
            expect(mockFetch).not.toHaveBeenCalled();
            subtleSignSpy.mockRestore();
        });
    });
});
