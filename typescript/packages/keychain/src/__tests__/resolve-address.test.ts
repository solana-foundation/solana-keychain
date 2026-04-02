import type { Address } from '@solana/addresses';
import type { SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode } from '@solana/keychain-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { KeychainSignerConfig } from '../types.js';

const TEST_ADDRESS = '11111111111111111111111111111111' as Address;

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
        it.each(['aws-kms', 'gcp-kms', 'turnkey', 'vault'] as const)('%s returns publicKey directly', async backend => {
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

    describe('async backends (fetch from API)', () => {
        it.each(['crossmint', 'dfns', 'fireblocks', 'para', 'privy'] as const)(
            '%s delegates to createKeychainSigner',
            async backend => {
                const config = {
                    backend,
                    apiKey: 'k',
                    appId: 'a',
                    appSecret: 's',
                    authToken: 't',
                    credId: 'c',
                    privateKeyPem: 'p',
                    vaultAccountId: 'v',
                    walletId: 'w',
                    walletLocator: 'l',
                } as KeychainSignerConfig;

                const address = await resolveAddress(config);

                expect(address).toBe(TEST_ADDRESS);
                expect(createKeychainSigner).toHaveBeenCalledWith(config);
            },
        );
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
