import { beforeEach, describe, expect, it, vi } from 'vitest';

import { assertIsSolanaSigner } from '@solana/keychain-core';

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

import { ParaSigner } from '../para-signer.js';

// Mock fetch globally
global.fetch = vi.fn();

// Valid 64-byte Ed25519 signature as 128 hex chars
const MOCK_SIGNATURE = 'ab'.repeat(64);

const MOCK_ADDRESS = '11111111111111111111111111111111';

const mockConfig = {
    apiKey: 'sk_test_api_key',
    apiBaseUrl: 'https://api.test.getpara.com',
    walletId: '00000000-0000-0000-0000-000000000000',
};

function mockWalletResponse(overrides?: Record<string, unknown>) {
    return new Response(
        JSON.stringify({
            address: MOCK_ADDRESS,
            id: '00000000-0000-0000-0000-000000000000',
            publicKey: MOCK_ADDRESS,
            status: 'ready',
            type: 'SOLANA',
            ...overrides,
        }),
        { status: 200 },
    );
}

function mockSignResponse(signature = MOCK_SIGNATURE) {
    return new Response(JSON.stringify({ signature }), { status: 200 });
}

describe('ParaSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('create', () => {
        it('should create a signer by fetching wallet address', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await ParaSigner.create(mockConfig);

            expect(signer.address).toBe(MOCK_ADDRESS);
            expect(fetch).toHaveBeenCalledWith(
                'https://api.test.getpara.com/v1/wallets/00000000-0000-0000-0000-000000000000',
                expect.objectContaining({
                    headers: { 'X-API-Key': 'sk_test_api_key' },
                    method: 'GET',
                }),
            );
        });

        it('should satisfy the SolanaSigner interface', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await ParaSigner.create(mockConfig);

            assertIsSolanaSigner(signer);
        });

        it('should throw CONFIG_ERROR for missing apiKey', async () => {
            await expect(ParaSigner.create({ ...mockConfig, apiKey: '' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('Missing required configuration fields'),
            });
        });

        it('should throw CONFIG_ERROR for missing walletId', async () => {
            await expect(ParaSigner.create({ ...mockConfig, walletId: '' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('Missing required configuration fields'),
            });
        });

        it('should throw CONFIG_ERROR for non-sk_ apiKey', async () => {
            await expect(ParaSigner.create({ ...mockConfig, apiKey: 'pk_test_key' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiKey must be a Para secret key'),
            });
        });

        it('should throw CONFIG_ERROR for non-UUID walletId', async () => {
            await expect(ParaSigner.create({ ...mockConfig, walletId: 'not-a-uuid' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('walletId must be a valid UUID'),
            });
        });

        it('should throw CONFIG_ERROR for non-HTTPS apiBaseUrl', async () => {
            await expect(
                ParaSigner.create({ ...mockConfig, apiBaseUrl: 'http://api.getpara.com' }),
            ).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl must use HTTPS'),
            });
        });

        it('should throw CONFIG_ERROR for invalid apiBaseUrl', async () => {
            await expect(ParaSigner.create({ ...mockConfig, apiBaseUrl: 'not-a-url' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl is not a valid URL'),
            });
        });

        it('should throw CONFIG_ERROR for non-SOLANA wallet type', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse({ type: 'EVM' }));

            await expect(ParaSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('Expected SOLANA wallet but got EVM'),
            });
        });

        it('should throw REMOTE_API_ERROR when wallet has no address', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse({ address: null }));

            await expect(ParaSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('does not have an address'),
            });
        });

        it('should throw REMOTE_API_ERROR when API returns error', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            await expect(ParaSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Failed to fetch wallet'),
            });
        });

        it('should throw HTTP_ERROR when network fails', async () => {
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

            await expect(ParaSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Para network request failed'),
            });
        });

        it('should remove trailing slash from apiBaseUrl', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            await ParaSigner.create({ ...mockConfig, apiBaseUrl: 'https://api.test.getpara.com/' });

            expect(fetch).toHaveBeenCalledWith(
                'https://api.test.getpara.com/v1/wallets/00000000-0000-0000-0000-000000000000',
                expect.anything(),
            );
        });

        it('should throw CONFIG_ERROR for negative requestDelayMs', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            await expect(ParaSigner.create({ ...mockConfig, requestDelayMs: -1 })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('requestDelayMs must not be negative'),
            });
        });

        it('should warn for high requestDelayMs', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

            await ParaSigner.create({ ...mockConfig, requestDelayMs: 3001 });

            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
            warnSpy.mockRestore();
        });
    });

    describe('isAvailable', () => {
        it('should return true when wallet is ready', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockWalletResponse({ status: 'ready' })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(true);
        });

        it('should return true when wallet status is ACTIVE', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockWalletResponse({ status: 'ACTIVE' })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(true);
        });

        it('should return true when wallet status is mixed case', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockWalletResponse({ status: 'Ready' })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(true);
        });

        it('should return false when wallet is not ready', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockWalletResponse({ status: 'creating' })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when wallet type is not SOLANA', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockWalletResponse({ type: 'EVM', status: 'ready' })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when API returns error', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(new Response('', { status: 500 })); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });

        it('should return false when network fails', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockRejectedValueOnce(new Error('Network error')); // isAvailable

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.isAvailable();

            expect(result).toBe(false);
        });
    });

    describe('signMessages', () => {
        it('should sign a message successfully', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse()); // sign

            const signer = await ParaSigner.create(mockConfig);
            const message = {
                content: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            };

            const [result] = await signer.signMessages([message]);

            expect(result).toHaveProperty(MOCK_ADDRESS);
            expect(fetch).toHaveBeenLastCalledWith(
                'https://api.test.getpara.com/v1/wallets/00000000-0000-0000-0000-000000000000/sign-raw',
                expect.objectContaining({
                    body: JSON.stringify({ data: '01020304', encoding: 'hex' }),
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': 'sk_test_api_key',
                    },
                    method: 'POST',
                }),
            );
        });

        it('should return empty array for empty input', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.signMessages([]);

            expect(result).toEqual([]);
        });

        it('should handle 0x-prefixed signatures', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse('0x' + MOCK_SIGNATURE)); // sign

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            const [result] = await signer.signMessages([message]);

            expect(result).toHaveProperty(MOCK_ADDRESS);
        });

        it('should throw REMOTE_API_ERROR on API error', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'rate limited' }), { status: 429 }));

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Para signing failed'),
            });
        });

        it('should throw HTTP_ERROR on network failure', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockRejectedValueOnce(new Error('Network failure'));

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Para network request failed'),
            });
        });

        it('should throw REMOTE_API_ERROR for missing signature', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }));

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signature in Para response'),
            });
        });

        it('should throw PARSING_ERROR for invalid signature length', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse('aabb')); // too short

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Invalid Ed25519 signature length'),
            });
        });

        it('should throw PARSING_ERROR for non-hex characters in signature', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse('zz'.repeat(64))); // invalid hex

            const signer = await ParaSigner.create(mockConfig);
            const message = { content: new Uint8Array([1, 2, 3, 4]), signatures: {} };

            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Invalid hex characters'),
            });
        });

        it('should apply request delay for multiple messages', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse()) // sign 1
                .mockResolvedValueOnce(mockSignResponse()) // sign 2
                .mockResolvedValueOnce(mockSignResponse()); // sign 3

            const delaySpy = vi.spyOn(global, 'setTimeout');
            const signer = await ParaSigner.create({ ...mockConfig, requestDelayMs: 100 });

            const messages = [
                { content: new Uint8Array([1, 2, 3, 4]), signatures: {} },
                { content: new Uint8Array([5, 6, 7, 8]), signatures: {} },
                { content: new Uint8Array([9, 10, 11, 12]), signatures: {} },
            ];

            await signer.signMessages(messages);

            // First message has no delay, second has 100ms, third has 200ms
            expect(delaySpy).toHaveBeenCalledTimes(2);
            expect(delaySpy).toHaveBeenNthCalledWith(1, expect.any(Function), 100);
            expect(delaySpy).toHaveBeenNthCalledWith(2, expect.any(Function), 200);

            delaySpy.mockRestore();
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction successfully', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse()); // sign

            const signer = await ParaSigner.create(mockConfig);
            const mockTransaction = {
                messageBytes: new Uint8Array([1, 2, 3, 4]),
                signatures: {},
            } as any;

            const [result] = await signer.signTransactions([mockTransaction]);

            expect(result).toHaveProperty(MOCK_ADDRESS);
            expect(fetch).toHaveBeenLastCalledWith(
                'https://api.test.getpara.com/v1/wallets/00000000-0000-0000-0000-000000000000/sign-raw',
                expect.objectContaining({
                    body: JSON.stringify({ data: '01020304', encoding: 'hex' }),
                    method: 'POST',
                }),
            );
        });

        it('should return empty array for empty input', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockWalletResponse());

            const signer = await ParaSigner.create(mockConfig);
            const result = await signer.signTransactions([]);

            expect(result).toEqual([]);
        });

        it('should sign multiple transactions', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(mockSignResponse()) // sign 1
                .mockResolvedValueOnce(mockSignResponse()); // sign 2

            const signer = await ParaSigner.create(mockConfig);
            const transactions = [
                { messageBytes: new Uint8Array([1, 2]), signatures: {} } as any,
                { messageBytes: new Uint8Array([3, 4]), signatures: {} } as any,
            ];

            const results = await signer.signTransactions(transactions);

            expect(results).toHaveLength(2);
            expect(results[0]).toHaveProperty(MOCK_ADDRESS);
            expect(results[1]).toHaveProperty(MOCK_ADDRESS);
        });

        it('should throw REMOTE_API_ERROR on API error', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'rate limited' }), { status: 429 }));

            const signer = await ParaSigner.create(mockConfig);
            const mockTransaction = { messageBytes: new Uint8Array([1, 2, 3, 4]), signatures: {} } as any;

            await expect(signer.signTransactions([mockTransaction])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Para signing failed'),
            });
        });

        it('should throw HTTP_ERROR on network failure', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockWalletResponse()) // create
                .mockRejectedValueOnce(new Error('Network failure'));

            const signer = await ParaSigner.create(mockConfig);
            const mockTransaction = { messageBytes: new Uint8Array([1, 2, 3, 4]), signatures: {} } as any;

            await expect(signer.signTransactions([mockTransaction])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Para network request failed'),
            });
        });
    });
});
