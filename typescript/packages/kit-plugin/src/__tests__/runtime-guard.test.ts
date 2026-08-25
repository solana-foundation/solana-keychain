import type { Address, SignatureBytes, Transaction } from '@solana/kit';
import { createClient } from '@solana/kit';
import { describe, expect, it, vi } from 'vitest';

import { keychainIdentity, keychainPayer, keychainSigner } from '../keychain-plugin.js';

const FAKE_SENDING_SIGNER = {
    address: 'BLDprCsFyPBSyJDbYYbJXQWvexEuoUJP1zEbrVnNNaR3' as Address,
    isAvailable: () => Promise.resolve(true),
    signAndSendTransactions: (transactions: readonly Transaction[]) =>
        Promise.resolve(transactions.map(() => new Uint8Array(64) as SignatureBytes)),
};

const FAKE_MODIFYING_SIGNER = {
    address: 'BLDprCsFyPBSyJDbYYbJXQWvexEuoUJP1zEbrVnNNaR3' as Address,
    isAvailable: () => Promise.resolve(true),
    modifyAndSignTransactions: (transactions: readonly Transaction[]) => Promise.resolve(transactions),
};

vi.mock('@solana/keychain', async importOriginal => {
    const actual = await importOriginal<typeof import('@solana/keychain')>();
    return {
        ...actual,
        createKeychainSigner: vi.fn(() => Promise.resolve(FAKE_SENDING_SIGNER)),
    };
});

// The type-level managed-broadcast exclusion does not protect JS callers, so
// each plugin must refuse a managed-broadcast config at runtime.
describe('runtime guard against managed-broadcast signers', () => {
    const CROSSMINT_CONFIG = { apiKey: 'k', backend: 'crossmint', walletLocator: 'w' } as never;
    const FORDEFI_NATIVE_CONFIG = {
        accessToken: 't',
        backend: 'fordefi',
        chain: 'solana_mainnet',
        privateKeyPem: 'p',
        publicKey: 'x',
        vaultId: 'v',
    } as never;
    const FORDEFI_MANUAL_CONFIG = {
        accessToken: 't',
        backend: 'fordefi',
        chain: 'solana_mainnet',
        privateKeyPem: 'p',
        publicKey: 'x',
        pushMode: 'manual',
        vaultId: 'v',
    } as never;

    it('keychainSigner rejects a crossmint config before constructing the signer', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();

        await expect(createClient().use(keychainSigner(CROSSMINT_CONFIG))).rejects.toThrow(
            /cannot serve as a Kit client/,
        );
        expect(createKeychainSigner).not.toHaveBeenCalled();
    });

    it('keychainPayer rejects a crossmint config before constructing the signer', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();

        await expect(createClient().use(keychainPayer(CROSSMINT_CONFIG))).rejects.toThrow(
            /cannot serve as a Kit client/,
        );
        expect(createKeychainSigner).not.toHaveBeenCalled();
    });

    it('keychainIdentity rejects a crossmint config before constructing the signer', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();

        await expect(createClient().use(keychainIdentity(CROSSMINT_CONFIG))).rejects.toThrow(
            /cannot serve as a Kit client/,
        );
        expect(createKeychainSigner).not.toHaveBeenCalled();
    });

    it('rejects a fordefi native auto-mode config before constructing the signer', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();

        await expect(createClient().use(keychainSigner(FORDEFI_NATIVE_CONFIG))).rejects.toThrow(
            /cannot serve as a Kit client/,
        );
        expect(createKeychainSigner).not.toHaveBeenCalled();
    });

    it('keychainIdentity rejects a fordefi native manual-mode config before constructing the signer', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();

        await expect(createClient().use(keychainIdentity(FORDEFI_MANUAL_CONFIG))).rejects.toMatchObject({
            code: 'SIGNER_CONFIG_ERROR',
        });
        expect(createKeychainSigner).not.toHaveBeenCalled();
    });

    it('lets a fordefi native manual-mode config through to the factory', async () => {
        const { createKeychainSigner } = await import('@solana/keychain');
        vi.mocked(createKeychainSigner).mockClear();
        vi.mocked(createKeychainSigner).mockResolvedValueOnce(FAKE_MODIFYING_SIGNER as never);

        const client = await createClient().use(keychainSigner(FORDEFI_MANUAL_CONFIG));

        expect(createKeychainSigner).toHaveBeenCalled();
        // Kit runs a modifying signer ahead of the partial signers, so it is a
        // valid payer/identity and must survive the shape assertion.
        expect(client.payer).toBe(FAKE_MODIFYING_SIGNER);
    });

    it('rejects a factory that returns a signer without partial-signing methods', async () => {
        const config = { backend: 'memory', privateKey: new Uint8Array(32) } as never;

        await expect(createClient().use(keychainSigner(config))).rejects.toThrow(/EXPECTED_SOLANA_SIGNER/);
    });
});
