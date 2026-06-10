import * as nodeCrypto from 'node:crypto';

import { describe, it, expect, vi, beforeEach } from 'vitest';

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

import { DfnsSigner } from '../dfns-signer.js';
import {
    TEST_AUTH_TOKEN,
    TEST_CRED_ID,
    TEST_ED25519_PEM,
    TEST_WALLET_ID,
    createSignatureResponse,
    createUserActionInitResponse,
    createUserActionResponse,
    createWalletResponse,
} from './setup.js';

global.fetch = vi.fn();
const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

const defaultConfig = {
    authToken: TEST_AUTH_TOKEN,
    credId: TEST_CRED_ID,
    privateKeyPem: TEST_ED25519_PEM,
    walletId: TEST_WALLET_ID,
};

function mockWalletFetch(overrides?: Parameters<typeof createWalletResponse>[0]) {
    mockFetch.mockResolvedValueOnce({
        json: async () => createWalletResponse(overrides),
        ok: true,
    });
}

describe('DfnsSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('create', () => {
        it('creates a DfnsSigner with valid config', async () => {
            mockWalletFetch();
            const signer = await DfnsSigner.create(defaultConfig);
            expect(signer).toBeDefined();
            expect(signer.address).toBeDefined();
        });

        it('throws error for missing authToken', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, authToken: '' })).rejects.toThrow(
                'Missing required authToken field',
            );
        });

        it('throws error for missing credId', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, credId: '' })).rejects.toThrow(
                'Missing required credId field',
            );
        });

        it('throws error for missing privateKeyPem', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, privateKeyPem: '' })).rejects.toThrow(
                'Missing required privateKeyPem field',
            );
        });

        it('throws error for missing walletId', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, walletId: '' })).rejects.toThrow(
                'Missing required walletId field',
            );
        });

        it('throws CONFIG_ERROR when apiBaseUrl is not a valid URL', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, apiBaseUrl: 'not-a-url' })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl is not a valid URL'),
            });
        });

        it('throws CONFIG_ERROR when apiBaseUrl does not use HTTPS', async () => {
            await expect(
                DfnsSigner.create({
                    ...defaultConfig,
                    apiBaseUrl: 'http://api.dfns.test',
                }),
            ).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
                message: expect.stringContaining('apiBaseUrl must use HTTPS'),
            });
        });

        it('throws error for inactive wallet', async () => {
            mockWalletFetch({ status: 'Inactive' });
            await expect(DfnsSigner.create(defaultConfig)).rejects.toThrow('not active');
        });

        it('throws error for non-EdDSA scheme', async () => {
            mockWalletFetch({ scheme: 'ECDSA' });
            await expect(DfnsSigner.create(defaultConfig)).rejects.toThrow('Unsupported key scheme');
        });

        it('throws error for API failure', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
            });
            await expect(DfnsSigner.create(defaultConfig)).rejects.toThrow();
        });

        it('throws PARSING_ERROR for malformed wallet response shape', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => ({}),
                ok: true,
            });

            await expect(DfnsSigner.create(defaultConfig)).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Unexpected Dfns wallet response shape'),
            });
        });

        it('throws error for negative requestDelayMs', async () => {
            await expect(DfnsSigner.create({ ...defaultConfig, requestDelayMs: -1 })).rejects.toThrow(
                'requestDelayMs must not be negative',
            );
        });

        it('warns for high requestDelayMs', async () => {
            const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
            mockWalletFetch();
            await DfnsSigner.create({ ...defaultConfig, requestDelayMs: 5000 });
            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
            warnSpy.mockRestore();
        });

        it('throws HTTP_ERROR when fetch fails during create', async () => {
            mockFetch.mockRejectedValueOnce(new Error('Network timeout'));
            await expect(DfnsSigner.create(defaultConfig)).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Dfns network request failed'),
            });
        });
    });

    describe('signMessages', () => {
        it('throws HTTP_ERROR when fetch fails during signing', async () => {
            mockWalletFetch();
            const signer = await DfnsSigner.create(defaultConfig);

            // The auth flow init request fails with network error
            mockFetch.mockRejectedValueOnce(new Error('Network timeout'));

            await expect(
                signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Dfns network request failed'),
            });
        });

        it('signs a message successfully', async () => {
            const rHex = '11'.repeat(32);
            const sHex = '22'.repeat(32);

            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createSignatureResponse(rHex, sHex),
                ok: true,
            });

            const signer = await DfnsSigner.create(defaultConfig);

            const result = await signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();

            const sig = result[0]![signer.address]!;
            expect(sig.length).toBe(64);
        });

        it('accepts escaped-newline PEM keys for auth challenge signing', async () => {
            const rHex = '11'.repeat(32);
            const sHex = '22'.repeat(32);

            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createSignatureResponse(rHex, sHex),
                ok: true,
            });

            const signer = await DfnsSigner.create({
                ...defaultConfig,
                privateKeyPem: TEST_ED25519_PEM.replace(/\n/g, '\\n'),
            });

            const result = await signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]);

            expect(result).toHaveLength(1);
            const sig = result[0]![signer.address]!;
            expect(sig.length).toBe(64);
        });

        it('supports SEC1 PEM keys for auth challenge signing', async () => {
            const { privateKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
            const sec1Pem = privateKey.export({ format: 'pem', type: 'sec1' }).toString();
            const rHex = '11'.repeat(32);
            const sHex = '22'.repeat(32);

            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createSignatureResponse(rHex, sHex),
                ok: true,
            });

            const signer = await DfnsSigner.create({
                ...defaultConfig,
                privateKeyPem: sec1Pem,
            });

            const result = await signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]);

            expect(result).toHaveLength(1);
            const sig = result[0]![signer.address]!;
            expect(sig.length).toBe(64);
        });

        it('left-pads short signature components', async () => {
            // r is 31 bytes (short by 1), s is 32 bytes
            const rHex = 'ff'.repeat(31);
            const sHex = 'aa'.repeat(32);

            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createSignatureResponse(rHex, sHex),
                ok: true,
            });

            const signer = await DfnsSigner.create(defaultConfig);

            const result = await signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]);

            const sig = result[0]![signer.address]!;
            expect(sig.length).toBe(64);
            // First byte should be 0x00 (left-pad), then 31 bytes of 0xff
            expect(sig[0]).toBe(0x00);
            expect(sig[1]).toBe(0xff);
        });

        it('throws PARSING_ERROR for malformed auth challenge response shape', async () => {
            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => ({}),
                ok: true,
            });

            const signer = await DfnsSigner.create(defaultConfig);

            await expect(
                signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Unexpected Dfns auth challenge response shape'),
            });
        });

        it('throws PARSING_ERROR for malformed signature response shape', async () => {
            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => ({}),
                ok: true,
            });

            const signer = await DfnsSigner.create(defaultConfig);

            await expect(
                signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Unexpected Dfns signature response shape'),
            });
        });

        it('throws PARSING_ERROR for malformed auth action response shape', async () => {
            mockWalletFetch();

            mockFetch.mockResolvedValueOnce({
                json: async () => createUserActionInitResponse(),
                ok: true,
            });

            mockFetch.mockResolvedValueOnce({
                json: async () => ({}),
                ok: true,
            });

            const signer = await DfnsSigner.create(defaultConfig);

            await expect(
                signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]),
            ).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Unexpected Dfns auth action response shape'),
            });
        });
    });

    describe('isAvailable', () => {
        it('returns true when API responds', async () => {
            mockWalletFetch();
            // isAvailable doesn't need create(), but we need a signer instance
            mockWalletFetch(); // for the isAvailable call
            const signer = await DfnsSigner.create(defaultConfig);
            expect(await signer.isAvailable()).toBe(true);
        });

        it('returns false when API fails', async () => {
            mockWalletFetch(); // for create()
            const signer = await DfnsSigner.create(defaultConfig);

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
            });
            expect(await signer.isAvailable()).toBe(false);
        });
    });
});
