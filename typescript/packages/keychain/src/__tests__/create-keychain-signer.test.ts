import type { Address } from '@solana/addresses';
import type { SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode } from '@solana/keychain-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createKeychainSigner } from '../create-keychain-signer.js';
import type { BackendName, KeychainSignerConfig } from '../types.js';

const TEST_ADDRESS = '11111111111111111111111111111111' as Address;

function makeMockSigner(address: Address = TEST_ADDRESS): SolanaSigner {
    return {
        address,
        isAvailable: vi.fn().mockResolvedValue(true),
        signMessages: vi.fn().mockResolvedValue([]),
        signTransactions: vi.fn().mockResolvedValue([]),
    } as unknown as SolanaSigner;
}

// Mock all backend factories
vi.mock('@solana/keychain-aws-kms', () => ({ createAwsKmsSigner: vi.fn() }));
vi.mock('@solana/keychain-cdp', () => ({ createCdpSigner: vi.fn() }));
vi.mock('@solana/keychain-crossmint', () => ({ createCrossmintSigner: vi.fn() }));
vi.mock('@solana/keychain-dfns', () => ({ createDfnsSigner: vi.fn() }));
vi.mock('@solana/keychain-fireblocks', () => ({ createFireblocksSigner: vi.fn() }));
vi.mock('@solana/keychain-fordefi', () => ({ createFordefiSigner: vi.fn() }));
vi.mock('@solana/keychain-gcp-kms', () => ({ createGcpKmsSigner: vi.fn() }));
vi.mock('@solana/keychain-memory', () => ({ createMemorySigner: vi.fn() }));
vi.mock('@solana/keychain-openfort', () => ({ createOpenfortSigner: vi.fn() }));
vi.mock('@solana/keychain-para', () => ({ createParaSigner: vi.fn() }));
vi.mock('@solana/keychain-privy', () => ({ createPrivySigner: vi.fn() }));
vi.mock('@solana/keychain-turnkey', () => ({ createTurnkeySigner: vi.fn() }));
vi.mock('@solana/keychain-utila', () => ({ createUtilaSigner: vi.fn() }));
vi.mock('@solana/keychain-vault', () => ({ createVaultSigner: vi.fn() }));

// Table-driven test configs — one per backend; `satisfies` makes a missing backend a typecheck failure
const BACKEND_CONFIGS = {
    'aws-kms': {
        config: { backend: 'aws-kms', keyId: 'key-1', publicKey: TEST_ADDRESS },
        factoryName: 'createAwsKmsSigner',
        modulePath: '@solana/keychain-aws-kms',
    },
    cdp: {
        config: {
            backend: 'cdp',
            address: TEST_ADDRESS,
            cdpApiKeyId: 'id',
            cdpApiKeySecret: 's',
            cdpWalletSecret: 'w',
        },
        factoryName: 'createCdpSigner',
        modulePath: '@solana/keychain-cdp',
    },
    crossmint: {
        config: { backend: 'crossmint', apiKey: 'key', walletLocator: 'loc' },
        factoryName: 'createCrossmintSigner',
        modulePath: '@solana/keychain-crossmint',
    },
    dfns: {
        config: { backend: 'dfns', authToken: 'tok', credId: 'cred', privateKeyPem: 'pem', walletId: 'w' },
        factoryName: 'createDfnsSigner',
        modulePath: '@solana/keychain-dfns',
    },
    fireblocks: {
        config: { backend: 'fireblocks', apiKey: 'key', privateKeyPem: 'pem', vaultAccountId: 'v' },
        factoryName: 'createFireblocksSigner',
        modulePath: '@solana/keychain-fireblocks',
    },
    fordefi: {
        config: {
            backend: 'fordefi',
            accessToken: 'token',
            privateKeyPem: 'pem',
            publicKey: TEST_ADDRESS,
            vaultId: 'vault',
        },
        factoryName: 'createFordefiSigner',
        modulePath: '@solana/keychain-fordefi',
    },
    'gcp-kms': {
        config: { backend: 'gcp-kms', keyName: 'key', publicKey: TEST_ADDRESS },
        factoryName: 'createGcpKmsSigner',
        modulePath: '@solana/keychain-gcp-kms',
    },
    memory: {
        config: { backend: 'memory', privateKeyString: 'irrelevant-mocked-string' },
        factoryName: 'createMemorySigner',
        modulePath: '@solana/keychain-memory',
    },
    openfort: {
        config: { backend: 'openfort', accountId: 'acc_1', secretKey: 'sk_test_1', walletSecret: 'ws' },
        factoryName: 'createOpenfortSigner',
        modulePath: '@solana/keychain-openfort',
    },
    para: {
        config: { backend: 'para', apiKey: 'key', walletId: 'w' },
        factoryName: 'createParaSigner',
        modulePath: '@solana/keychain-para',
    },
    privy: {
        config: { backend: 'privy', appId: 'app', appSecret: 'secret', walletId: 'w' },
        factoryName: 'createPrivySigner',
        modulePath: '@solana/keychain-privy',
    },
    turnkey: {
        config: {
            backend: 'turnkey',
            apiPrivateKey: 'pk',
            apiPublicKey: 'pub',
            organizationId: 'org',
            privateKeyId: 'pkid',
            publicKey: TEST_ADDRESS,
        },
        factoryName: 'createTurnkeySigner',
        modulePath: '@solana/keychain-turnkey',
    },
    utila: {
        config: {
            backend: 'utila',
            network: 'networks/solana-devnet',
            serviceAccountEmail: 'service-account@example.com',
            serviceAccountPrivateKeyPem: 'pem',
            vaultId: 'vault',
            walletId: 'wallet',
        },
        factoryName: 'createUtilaSigner',
        modulePath: '@solana/keychain-utila',
    },
    vault: {
        config: {
            backend: 'vault',
            keyName: 'key',
            publicKey: TEST_ADDRESS,
            vaultAddr: 'https://v',
            vaultToken: 'tok',
        },
        factoryName: 'createVaultSigner',
        modulePath: '@solana/keychain-vault',
    },
} satisfies Record<BackendName, { config: KeychainSignerConfig; factoryName: string; modulePath: string }>;

describe('createKeychainSigner', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe.each(Object.entries(BACKEND_CONFIGS))('%s', (_backend, { config, modulePath, factoryName }) => {
        it('dispatches to the correct factory', async () => {
            const mockSigner = makeMockSigner();
            const mod = await import(modulePath);
            const factory = mod[factoryName] as ReturnType<typeof vi.fn>;
            factory.mockResolvedValue(mockSigner);

            const result = await createKeychainSigner(config);

            expect(result).toBe(mockSigner);
            expect(factory).toHaveBeenCalledOnce();
        });

        it('passes config without the backend field', async () => {
            const mockSigner = makeMockSigner();
            const mod = await import(modulePath);
            const factory = mod[factoryName] as ReturnType<typeof vi.fn>;
            factory.mockResolvedValue(mockSigner);

            await createKeychainSigner(config);

            const passedConfig = factory.mock.calls[0]![0] as Record<string, unknown>;
            expect(passedConfig).not.toHaveProperty('backend');
        });

        it('propagates factory errors', async () => {
            const mod = await import(modulePath);
            const factory = mod[factoryName] as ReturnType<typeof vi.fn>;
            factory.mockRejectedValue(new Error('factory error'));

            await expect(createKeychainSigner(config)).rejects.toThrow('factory error');
        });
    });

    it('throws SignerError for unknown backend', async () => {
        const badConfig = { backend: 'nonexistent' } as unknown as KeychainSignerConfig;

        try {
            await createKeychainSigner(badConfig);
            expect.unreachable('should have thrown');
        } catch (error) {
            expect((error as { code: string }).code).toBe(SignerErrorCode.CONFIG_ERROR);
        }
    });

    it('preserves the Crossmint sending-signer type', async () => {
        const mod = await import('@solana/keychain-crossmint');
        const factory = mod.createCrossmintSigner as ReturnType<typeof vi.fn>;
        const mockSigner = {
            address: TEST_ADDRESS,
            isAvailable: vi.fn().mockResolvedValue(true),
            signAndSendTransactions: vi.fn().mockResolvedValue([]),
        };
        factory.mockResolvedValue(mockSigner);

        const signer = await createKeychainSigner({
            apiKey: 'key',
            backend: 'crossmint',
            walletLocator: 'loc',
        });

        expect(signer.signAndSendTransactions).toBe(mockSigner.signAndSendTransactions);
    });

    it('preserves the native Fordefi TransactionSendingSigner type', async () => {
        const mod = await import('@solana/keychain-fordefi');
        const factory = mod.createFordefiSigner as ReturnType<typeof vi.fn>;
        const mockSigner = {
            ...makeMockSigner(),
            signAndSendTransactions: vi.fn().mockResolvedValue([]),
        };
        factory.mockResolvedValue(mockSigner);

        const signer = await createKeychainSigner({
            accessToken: 'token',
            backend: 'fordefi',
            chain: 'solana_devnet',
            privateKeyPem: 'pem',
            publicKey: TEST_ADDRESS,
            vaultId: 'vault',
        });

        expect(signer.signAndSendTransactions).toBe(mockSigner.signAndSendTransactions);
    });

    it('preserves the native manual Fordefi TransactionModifyingSigner type', async () => {
        const mod = await import('@solana/keychain-fordefi');
        const factory = mod.createFordefiSigner as ReturnType<typeof vi.fn>;
        const mockSigner = {
            ...makeMockSigner(),
            modifyAndSignTransactions: vi.fn().mockResolvedValue([]),
        };
        factory.mockResolvedValue(mockSigner);

        const signer = await createKeychainSigner({
            accessToken: 'token',
            backend: 'fordefi',
            chain: 'solana_devnet',
            privateKeyPem: 'pem',
            publicKey: TEST_ADDRESS,
            pushMode: 'manual',
            vaultId: 'vault',
        });

        // The manual overload must resolve to the modifying shape, not the
        // sending one the plain `chain` overload returns.
        expect(signer.modifyAndSignTransactions).toBe(mockSigner.modifyAndSignTransactions);
    });
});
