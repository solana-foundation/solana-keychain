import type { Address } from '@solana/addresses';
import type { SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode } from '@solana/keychain-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { BackendName, KeychainSignerConfig } from '../types.js';

const TEST_ADDRESS = '11111111111111111111111111111111' as Address;

// How resolveAddress obtains each backend's address; `satisfies` makes a missing backend a typecheck failure
const BACKEND_RESOLUTION = {
    'aws-kms': 'publicKey',
    cdp: 'address',
    crossmint: 'factory',
    dfns: 'factory',
    fireblocks: 'factory',
    'gcp-kms': 'publicKey',
    memory: 'factory',
    openfort: 'factory',
    para: 'factory',
    privy: 'factory',
    turnkey: 'publicKey',
    utila: 'factory',
    vault: 'publicKey',
} satisfies Record<BackendName, 'address' | 'factory' | 'publicKey'>;

function backendsResolvedVia(kind: 'address' | 'factory' | 'publicKey'): BackendName[] {
    return (Object.keys(BACKEND_RESOLUTION) as BackendName[]).filter(backend => BACKEND_RESOLUTION[backend] === kind);
}

function makeMockSigner(address: Address = TEST_ADDRESS): SolanaSigner {
    return {
        address,
        isAvailable: vi.fn().mockResolvedValue(true),
        signMessages: vi.fn().mockResolvedValue([]),
        signTransactions: vi.fn().mockResolvedValue([]),
    } as unknown as SolanaSigner;
}

// Mock createKeychainSigner so we don't pull in all backend deps
vi.mock('../create-keychain-signer.js', () => ({
    createKeychainSigner: vi.fn().mockResolvedValue(makeMockSigner()),
}));

// Must import after mock setup
const { resolveAddress } = await import('../resolve-address.js');
const { createKeychainSigner } = await import('../create-keychain-signer.js');

describe('resolveAddress', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('sync backends (publicKey in config)', () => {
        it.each(backendsResolvedVia('publicKey'))('%s returns publicKey directly', async backend => {
            const config = {
                backend,
                keyId: 'k',
                keyName: 'k',
                publicKey: TEST_ADDRESS,
                vaultAddr: 'https://v',
                vaultToken: 't',
                apiPrivateKey: 'pk',
                apiPublicKey: 'pub',
                organizationId: 'org',
                privateKeyId: 'pkid',
            } as KeychainSignerConfig;

            const address = await resolveAddress(config);

            expect(address).toBe(TEST_ADDRESS);
            expect(createKeychainSigner).not.toHaveBeenCalled();
        });

        it('throws for invalid publicKey', async () => {
            const config = {
                backend: 'vault' as const,
                keyName: 'k',
                publicKey: 'not-a-valid-address',
                vaultAddr: 'https://v',
                vaultToken: 't',
            };

            await expect(resolveAddress(config as KeychainSignerConfig)).rejects.toThrow();
        });
    });

    describe('cdp (address in config)', () => {
        it('returns address directly', async () => {
            const config = {
                backend: 'cdp' as const,
                address: TEST_ADDRESS,
                cdpApiKeyId: 'id',
                cdpApiKeySecret: 's',
                cdpWalletSecret: 'w',
            };

            const address = await resolveAddress(config as KeychainSignerConfig);

            expect(address).toBe(TEST_ADDRESS);
            expect(createKeychainSigner).not.toHaveBeenCalled();
        });

        it('throws for invalid address', async () => {
            const config = {
                backend: 'cdp' as const,
                address: 'bad',
                cdpApiKeyId: 'id',
                cdpApiKeySecret: 's',
                cdpWalletSecret: 'w',
            };

            await expect(resolveAddress(config as KeychainSignerConfig)).rejects.toThrow();
        });
    });

    describe('async backends (fetch from API or derive locally)', () => {
        it.each(backendsResolvedVia('factory'))('%s delegates to createKeychainSigner', async backend => {
            const config = {
                backend,
                accountId: 'acc_1',
                apiKey: 'k',
                appId: 'a',
                appSecret: 's',
                authToken: 't',
                credId: 'c',
                privateKeyPem: 'p',
                privateKeyString: 'irrelevant-mocked-string',
                secretKey: 'sk_test_1',
                serviceAccountEmail: 'service-account@example.com',
                serviceAccountPrivateKeyPem: 'pem',
                network: 'networks/solana-devnet',
                vaultAccountId: 'v',
                vaultId: 'vault',
                walletId: 'w',
                walletLocator: 'l',
                walletSecret: 'ws',
            } as KeychainSignerConfig;

            const address = await resolveAddress(config);

            expect(address).toBe(TEST_ADDRESS);
            expect(createKeychainSigner).toHaveBeenCalledWith(config);
        });
    });

    it('throws SignerError for unknown backend', async () => {
        const badConfig = { backend: 'nonexistent' } as unknown as KeychainSignerConfig;

        try {
            await resolveAddress(badConfig);
            expect.unreachable('should have thrown');
        } catch (error) {
            expect((error as { code: string }).code).toBe(SignerErrorCode.CONFIG_ERROR);
        }
    });
});
