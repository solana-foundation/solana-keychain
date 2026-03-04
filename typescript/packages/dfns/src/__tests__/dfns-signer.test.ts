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
    });

    describe('signMessages', () => {
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
