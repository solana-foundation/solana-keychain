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

import { CdpSigner } from '../cdp-signer.js';
import type { CdpSignerConfig } from '../types.js';

// --- Valid test credentials ---
// Ed25519: 64 bytes of 0x42 (seed || placeholder pubkey)
const TEST_CDP_API_KEY_SECRET = Buffer.alloc(64, 0x42).toString('base64');

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
    0x04, 0x20,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
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

    describe('constructor', () => {
        it('creates a CdpSigner with valid config', () => {
            const signer = new CdpSigner(makeConfig());

            expect(signer.address).toBe(TEST_ADDRESS);
            assertIsSolanaSigner(signer);
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
        });

        it('throws CONFIG_ERROR for missing cdpApiKeyId', () => {
            expect(() => new CdpSigner(makeConfig({ cdpApiKeyId: '' }))).toThrow(
                'Missing required cdpApiKeyId field',
            );
        });

        it('throws CONFIG_ERROR for missing cdpApiKeySecret', () => {
            expect(() => new CdpSigner(makeConfig({ cdpApiKeySecret: '' }))).toThrow(
                'Missing required cdpApiKeySecret field',
            );
        });

        it('throws CONFIG_ERROR for missing cdpWalletSecret', () => {
            expect(() => new CdpSigner(makeConfig({ cdpWalletSecret: '' }))).toThrow(
                'Missing required cdpWalletSecret field',
            );
        });

        it('throws CONFIG_ERROR for missing address', () => {
            expect(() => new CdpSigner(makeConfig({ address: '' }))).toThrow(
                'Missing required address field',
            );
        });

        it('throws CONFIG_ERROR for invalid address', () => {
            expect(() => new CdpSigner(makeConfig({ address: 'not-a-valid-address' }))).toThrow(
                'Invalid Solana address format',
            );
        });

        it('throws CONFIG_ERROR for negative requestDelayMs', () => {
            expect(() => new CdpSigner(makeConfig({ requestDelayMs: -1 }))).toThrow(
                'requestDelayMs must not be negative',
            );
        });

        it('warns for high requestDelayMs', () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            new CdpSigner(makeConfig({ requestDelayMs: 5000 }));
            expect(warnSpy).toHaveBeenCalledWith(
                expect.stringContaining('requestDelayMs is greater than 3000ms'),
            );
            warnSpy.mockRestore();
        });

        it('accepts custom baseUrl', () => {
            const signer = new CdpSigner(makeConfig({ baseUrl: 'https://custom.example.com' }));
            expect(signer).toBeDefined();
        });

        it('accepts requestDelayMs of 0', () => {
            const signer = new CdpSigner(makeConfig({ requestDelayMs: 0 }));
            expect(signer).toBeDefined();
        });
    });

    describe('signMessages', () => {
        it('signs a message and returns a signature dictionary', async () => {
            // Base58-encoded 64-byte signature
            const base58Sig = '5LfnqEfGPFBaHHeQBiNkgQ2EPy4FkVLKE7cjMYc7gv6EjE8Vs5gqaXcZHjpxr3yj5TMt7j3JdJPkXfnwXxXiNAh';
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ signature: base58Sig }), { status: 200 }),
            );

            const signer = new CdpSigner(makeConfig());
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

            const signer = new CdpSigner(makeConfig({ requestDelayMs: 10 }));
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

            const signer = new CdpSigner(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow(
                'CDP signMessage network request failed',
            );
        });

        it('throws REMOTE_API_ERROR on non-2xx response', async () => {
            mockFetch.mockResolvedValue(new Response('{"error":"Unauthorized"}', { status: 401 }));

            const signer = new CdpSigner(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow(
                'CDP signMessage API error: 401',
            );
        });

        it('throws SIGNING_FAILED for invalid signature length', async () => {
            // Return a base58 string that decodes to != 64 bytes (small value)
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ signature: '1' }), { status: 200 }), // '1' decodes to 1 byte
            );

            const signer = new CdpSigner(makeConfig());
            const message = { content: new TextEncoder().encode('hello'), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow(
                'Invalid signature length',
            );
        });

        it('throws SERIALIZATION_ERROR for invalid UTF-8 message', async () => {
            const signer = new CdpSigner(makeConfig());
            const message = { content: new Uint8Array([0xff]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toThrow(
                'CDP signMessage requires a valid UTF-8 message',
            );
        });
    });

    describe('signTransactions', () => {
        it('accepts a key pair address as the signer address', async () => {
            const keyPair = await generateKeyPairSigner();
            const signer = new CdpSigner(makeConfig({ address: keyPair.address }));
            expect(signer.address).toBe(keyPair.address);
        });

        it('calls CDP signTransaction with the correct address and wire transaction', async () => {
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ signedTransaction: MOCK_B64_WIRE_TX }), { status: 200 }),
            );

            const signer = new CdpSigner(makeConfig());
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

            const signer = new CdpSigner(makeConfig());
            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow(
                'CDP signTransaction network request failed',
            );
        });

        it('throws REMOTE_API_ERROR on non-2xx response', async () => {
            mockFetch.mockResolvedValue(new Response('{"error":"Forbidden"}', { status: 403 }));

            const signer = new CdpSigner(makeConfig());
            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow(
                'CDP signTransaction API error: 403',
            );
        });
    });

    describe('isAvailable', () => {
        it('returns true when the account is accessible', async () => {
            mockFetch.mockResolvedValue(
                new Response(JSON.stringify({ address: TEST_ADDRESS }), { status: 200 }),
            );

            const signer = new CdpSigner(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(true);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
            expect(url).toContain(TEST_ADDRESS);
        });

        it('returns false when the account is not found', async () => {
            mockFetch.mockResolvedValue(new Response('', { status: 404 }));

            const signer = new CdpSigner(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('returns false when the CDP API is unreachable', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'));

            const signer = new CdpSigner(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });

        it('returns false on 401 unauthorized', async () => {
            mockFetch.mockResolvedValue(new Response('', { status: 401 }));

            const signer = new CdpSigner(makeConfig());
            const available = await signer.isAvailable();

            expect(available).toBe(false);
        });
    });
});
