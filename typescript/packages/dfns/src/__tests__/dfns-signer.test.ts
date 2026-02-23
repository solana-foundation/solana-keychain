import { describe, it, expect, vi, beforeEach } from 'vitest';

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

describe('DfnsSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('constructor', () => {
        it('creates a DfnsSigner with valid config', () => {
            const signer = new DfnsSigner(defaultConfig);
            expect(signer).toBeDefined();
        });

        it('throws error for missing authToken', () => {
            expect(() => {
                new DfnsSigner({ ...defaultConfig, authToken: '' });
            }).toThrow('Missing required authToken field');
        });

        it('throws error for missing credId', () => {
            expect(() => {
                new DfnsSigner({ ...defaultConfig, credId: '' });
            }).toThrow('Missing required credId field');
        });

        it('throws error for missing privateKeyPem', () => {
            expect(() => {
                new DfnsSigner({ ...defaultConfig, privateKeyPem: '' });
            }).toThrow('Missing required privateKeyPem field');
        });

        it('throws error for missing walletId', () => {
            expect(() => {
                new DfnsSigner({ ...defaultConfig, walletId: '' });
            }).toThrow('Missing required walletId field');
        });
    });

    describe('init', () => {
        it('initializes signer by fetching wallet', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse(),
                ok: true,
            });

            const signer = new DfnsSigner(defaultConfig);
            await signer.init();
            expect(signer.address).toBeDefined();
        });

        it('throws error for inactive wallet', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse({ status: 'Inactive' }),
                ok: true,
            });

            const signer = new DfnsSigner(defaultConfig);
            await expect(signer.init()).rejects.toThrow('not active');
        });

        it('throws error for non-EdDSA scheme', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse({ scheme: 'ECDSA' }),
                ok: true,
            });

            const signer = new DfnsSigner(defaultConfig);
            await expect(signer.init()).rejects.toThrow('Unsupported key scheme');
        });

        it('throws error for API failure', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
            });

            const signer = new DfnsSigner(defaultConfig);
            await expect(signer.init()).rejects.toThrow();
        });

        it('skips re-initialization', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse(),
                ok: true,
            });

            const signer = new DfnsSigner(defaultConfig);
            await signer.init();
            await signer.init();
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe('address', () => {
        it('throws when not initialized', () => {
            const signer = new DfnsSigner(defaultConfig);
            expect(() => signer.address).toThrow('not initialized');
        });
    });

    describe('signMessages', () => {
        it('signs a message successfully', async () => {
            const rHex = '11'.repeat(32);
            const sHex = '22'.repeat(32);

            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse(),
                ok: true,
            });

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

            const signer = new DfnsSigner(defaultConfig);
            await signer.init();

            const result = await signer.signMessages([{ content: new Uint8Array([1, 2, 3]), signatures: {} }]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();

            const sig = result[0]![signer.address]!;
            expect(sig.length).toBe(64);
        });
    });

    describe('isAvailable', () => {
        it('returns true when API responds', async () => {
            mockFetch.mockResolvedValueOnce({
                json: async () => createWalletResponse(),
                ok: true,
            });

            const signer = new DfnsSigner(defaultConfig);
            expect(await signer.isAvailable()).toBe(true);
        });

        it('returns false when API fails', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
            });

            const signer = new DfnsSigner(defaultConfig);
            expect(await signer.isAvailable()).toBe(false);
        });
    });
});
