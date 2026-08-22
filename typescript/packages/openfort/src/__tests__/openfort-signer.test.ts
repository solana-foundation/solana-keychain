import { Address } from '@solana/addresses';
import { assertIsSolanaSigner } from '@solana/keychain-core';
import { type Transaction, type TransactionWithinSizeLimit, type TransactionWithLifetime } from '@solana/transactions';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        // Stub the ed25519 verify so tests don't need to produce real signatures.
        assertSignatureValid: vi.fn(),
        sanitizeRemoteErrorResponse:
            mod.sanitizeRemoteErrorResponse ??
            ((text: string) =>
                `${text
                    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .slice(0, 256)} [truncated]`),
    };
});

import { createOpenfortSigner } from '../openfort-signer.js';
import type { OpenfortSignerConfig } from '../types.js';

// --- Test fixtures ---

// Valid P-256 PKCS#8 DER (scalar [0x01;32], in [1, n-1]) — base64-encoded.
// This is the bare single-line form an operator pastes into an env var.
const TEST_WALLET_SECRET_BASE64 = Buffer.from([
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
]).toString('base64');

// Same key wrapped in PEM headers — for the dual-format input test.
const TEST_WALLET_SECRET_PEM = `-----BEGIN PRIVATE KEY-----\n${TEST_WALLET_SECRET_BASE64}\n-----END PRIVATE KEY-----\n`;

const TEST_ADDRESS = '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV';
const TEST_ACCOUNT_ID = 'acc_e0b84653-1741-4a3d-9e91-2b0fd2942f60';
const TEST_BASE_URL = 'https://api.openfort.test';
const TEST_SECRET_KEY = 'sk_test_secret';

// 64-byte signature, hex-encoded with 0x prefix.
const TEST_SIGNATURE_HEX = `0x${'ab'.repeat(64)}`;

// Mock global fetch.
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function makeConfig(overrides?: Partial<OpenfortSignerConfig>): OpenfortSignerConfig {
    return {
        accountId: TEST_ACCOUNT_ID,
        baseUrl: TEST_BASE_URL,
        secretKey: TEST_SECRET_KEY,
        walletSecret: TEST_WALLET_SECRET_BASE64,
        ...overrides,
    };
}

function mockGetAccount(address: string = TEST_ADDRESS, status = 200) {
    mockFetch.mockImplementationOnce((url: string) => {
        expect(url).toBe(`${TEST_BASE_URL}/v2/accounts/${TEST_ACCOUNT_ID}`);
        return Promise.resolve(new Response(JSON.stringify({ address }), { status }));
    });
}

function mockSign(signatureHex: string = TEST_SIGNATURE_HEX, status = 200) {
    mockFetch.mockImplementationOnce(() =>
        Promise.resolve(
            new Response(
                JSON.stringify({
                    account: TEST_ACCOUNT_ID,
                    object: 'signature',
                    signature: signatureHex,
                }),
                { status },
            ),
        ),
    );
}

const createMockTransaction = (
    messageBytes: Uint8Array = new Uint8Array([1, 2, 3]),
): Transaction & TransactionWithinSizeLimit & TransactionWithLifetime => {
    return { messageBytes } as unknown as Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;
};

describe('OpenfortSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('create()', () => {
        it('fetches the address from /v2/accounts/{id} and returns a signer', async () => {
            mockGetAccount();

            const signer = await createOpenfortSigner(makeConfig());

            expect(signer.address).toBe(TEST_ADDRESS);
            assertIsSolanaSigner(signer);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
            expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${TEST_SECRET_KEY}`);
        });

        it('throws CONFIG_ERROR when secretKey is missing', async () => {
            await expect(createOpenfortSigner(makeConfig({ secretKey: '' }))).rejects.toThrow(
                'Missing required secretKey field',
            );
        });

        it('throws CONFIG_ERROR when accountId is missing', async () => {
            await expect(createOpenfortSigner(makeConfig({ accountId: '' }))).rejects.toThrow(
                'Missing required accountId field',
            );
        });

        it('throws CONFIG_ERROR when walletSecret is missing', async () => {
            await expect(createOpenfortSigner(makeConfig({ walletSecret: '' }))).rejects.toThrow(
                'Missing required walletSecret field',
            );
        });

        it('throws CONFIG_ERROR when walletSecret is not a valid P-256 key', async () => {
            await expect(createOpenfortSigner(makeConfig({ walletSecret: 'not-a-pem-key' }))).rejects.toThrow(
                'Failed to load P-256 PKCS#8 key',
            );
        });

        it('also accepts walletSecret in PEM form', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig({ walletSecret: TEST_WALLET_SECRET_PEM }));
            expect(signer.address).toBe(TEST_ADDRESS);
        });

        it('throws CONFIG_ERROR when baseUrl is not HTTPS', async () => {
            await expect(createOpenfortSigner(makeConfig({ baseUrl: 'http://api.openfort.io' }))).rejects.toMatchObject(
                {
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('baseUrl must use HTTPS'),
                },
            );
        });

        it('throws CONFIG_ERROR for negative requestDelayMs', async () => {
            await expect(createOpenfortSigner(makeConfig({ requestDelayMs: -1 }))).rejects.toThrow(
                'requestDelayMs must not be negative',
            );
        });

        it('throws REMOTE_API_ERROR when /v2/accounts returns 401', async () => {
            mockGetAccount(TEST_ADDRESS, 401);
            await expect(createOpenfortSigner(makeConfig())).rejects.toThrow('Openfort API error: 401');
        });

        it('throws CONFIG_ERROR when /v2/accounts returns a non-Solana address', async () => {
            mockGetAccount('0x742d35Cc6634C0532925a3b844Bc454e4438f44e');
            await expect(createOpenfortSigner(makeConfig())).rejects.toThrow('Openfort returned non-Solana address');
        });

        it('throws PARSING_ERROR when /v2/accounts response is invalid JSON', async () => {
            mockFetch.mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });
            await expect(createOpenfortSigner(makeConfig())).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Openfort response'),
            });
        });

        it('throws REMOTE_API_ERROR when /v2/accounts response is missing the address field', async () => {
            mockFetch.mockResolvedValueOnce({
                json: () => Promise.resolve({}),
                ok: true,
                status: 200,
            });
            await expect(createOpenfortSigner(makeConfig())).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing address in Openfort getAccount response'),
            });
        });
    });

    describe('signMessages', () => {
        it('hex-encodes the message bytes and POSTs them to /sign', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockSign();
            const result = await signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[TEST_ADDRESS as Address]).toBeInstanceOf(Uint8Array);
            // First call was getAccount, second call was sign.
            const [signUrl, signInit] = mockFetch.mock.calls[1] as [string, RequestInit];
            expect(signUrl).toBe(`${TEST_BASE_URL}/v2/accounts/backend/${TEST_ACCOUNT_ID}/sign`);
            expect(JSON.parse(signInit.body as string)).toEqual({ data: '0x6869' });
            const headers = signInit.headers as Headers;
            expect(headers.get('Authorization')).toBe(`Bearer ${TEST_SECRET_KEY}`);
            expect(headers.get('x-wallet-auth')).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
        });

        it('throws SIGNING_FAILED when the signature is the wrong length', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockSign('0x1234');
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toThrow('Invalid signature length');
        });

        it('throws PARSING_ERROR when the signature is not valid hex', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockSign('0xZZZZ');
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toThrow('Failed to hex-decode Openfort signature');
        });

        it('throws REMOTE_API_ERROR on non-2xx', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockFetch.mockResolvedValueOnce(new Response('{"error":"unauthorized"}', { status: 401 }));
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toThrow('Openfort API error: 401');
        });

        it('throws HTTP_ERROR on network failure', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockFetch.mockRejectedValueOnce(new Error('Network error'));
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toThrow('Openfort network request failed');
        });

        it('throws PARSING_ERROR when sign response is invalid JSON', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockFetch.mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Openfort response'),
            });
        });

        it('throws REMOTE_API_ERROR when sign response is missing the signature field', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockFetch.mockResolvedValueOnce({
                json: () => Promise.resolve({}),
                ok: true,
                status: 200,
            });
            await expect(
                signer.signMessages([{ content: new TextEncoder().encode('hi'), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signature in Openfort response'),
            });
        });

        it('delays subsequent requests by requestDelayMs', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig({ requestDelayMs: 30 }));

            // mockImplementation so each concurrent call gets a fresh Response (body can only be read once).
            mockFetch.mockImplementation(() =>
                Promise.resolve(
                    new Response(
                        JSON.stringify({
                            account: TEST_ACCOUNT_ID,
                            object: 'signature',
                            signature: TEST_SIGNATURE_HEX,
                        }),
                        { status: 200 },
                    ),
                ),
            );

            const messages = [
                { content: new TextEncoder().encode('one'), signatures: {} },
                { content: new TextEncoder().encode('two'), signatures: {} },
                { content: new TextEncoder().encode('three'), signatures: {} },
            ];

            const startTime = Date.now();
            const result = await signer.signMessages(messages);
            const elapsed = Date.now() - startTime;

            expect(result).toHaveLength(3);
            // Indexes 0, 1, 2 → delays 0, 30, 60ms. Total wall time is dominated by the longest.
            // Allow a small slop below 60 to avoid timer flakiness.
            expect(elapsed).toBeGreaterThanOrEqual(55);
        });
    });

    describe('signTransactions', () => {
        it("POSTs the transaction's messageBytes hex-encoded to /sign", async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockSign();
            const tx = createMockTransaction(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
            const result = await signer.signTransactions([tx]);

            expect(result).toHaveLength(1);
            const [, init] = mockFetch.mock.calls[1] as [string, RequestInit];
            expect(JSON.parse(init.body as string)).toEqual({ data: '0xdeadbeef' });
        });
    });

    describe('isAvailable', () => {
        it('returns true when /v2/accounts still resolves to the same address', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockGetAccount(TEST_ADDRESS);
            expect(await signer.isAvailable()).toBe(true);
        });

        it('returns false when the address has changed', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockGetAccount('FdJqs1XSREL5KPxX67YyQp9w6q8KEj1k4r6JBYGxJpvN');
            expect(await signer.isAvailable()).toBe(false);
        });

        it('returns false when /v2/accounts returns 401', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockGetAccount(TEST_ADDRESS, 401);
            expect(await signer.isAvailable()).toBe(false);
        });

        it('returns false on network failure', async () => {
            mockGetAccount();
            const signer = await createOpenfortSigner(makeConfig());

            mockFetch.mockRejectedValueOnce(new Error('Network error'));
            expect(await signer.isAvailable()).toBe(false);
        });
    });
});
