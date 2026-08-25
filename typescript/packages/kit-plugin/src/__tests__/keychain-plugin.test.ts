import { createClient } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { keychainIdentity, keychainPayer, keychainSigner } from '../keychain-plugin.js';

const TEST_SEED = new Uint8Array(32).fill(7);
const MEMORY_CONFIG = { backend: 'memory', privateKey: TEST_SEED } as const;

describe('keychainSigner', () => {
    it('sets the same signer as both payer and identity', async () => {
        const client = await createClient().use(keychainSigner(MEMORY_CONFIG));

        expect(client.payer).toBe(client.identity);
        expect(client.payer.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    });

    it('preserves existing client properties', async () => {
        const base = { rpc: 'fake-rpc' };
        const extended = await keychainSigner(MEMORY_CONFIG)(base);

        expect(extended.rpc).toBe('fake-rpc');
        expect(extended.payer.address).toBe(extended.identity.address);
    });

    it('installs a functional signer', async () => {
        const client = await createClient().use(keychainSigner(MEMORY_CONFIG));

        // client.payer must stay a statically known partial signer: no casts.
        expect(typeof client.payer.signTransactions).toBe('function');
        expect(typeof client.payer.signMessages).toBe('function');
        await expect(client.payer.isAvailable()).resolves.toBe(true);
    });
});

describe('keychainPayer', () => {
    it('sets only the payer', async () => {
        const client = await createClient().use(keychainPayer(MEMORY_CONFIG));

        expect(client.payer.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
        expect(client).not.toHaveProperty('identity');
    });
});

describe('keychainIdentity', () => {
    it('sets only the identity', async () => {
        const client = await createClient().use(keychainIdentity(MEMORY_CONFIG));

        expect(client.identity.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
        expect(client).not.toHaveProperty('payer');
    });
});

describe('managed-broadcast exclusion', () => {
    it('rejects managed-broadcast configs at the type level', () => {
        // Building the plugin never constructs a signer — that happens when the
        // plugin is applied to a client — so these calls are side-effect free.
        // @ts-expect-error Crossmint broadcasts server-side and cannot be a client payer/identity
        keychainSigner({ apiKey: 'k', backend: 'crossmint', walletLocator: 'w' });
        // @ts-expect-error Fordefi native auto mode broadcasts server-side
        keychainPayer({
            accessToken: 't',
            backend: 'fordefi',
            chain: 'solana_mainnet',
            privateKeyPem: 'p',
            publicKey: 'x',
            vaultId: 'v',
        });
        // Fordefi black-box mode (no chain) is a partial signer and stays accepted.
        const plugin = keychainIdentity({
            accessToken: 't',
            backend: 'fordefi',
            privateKeyPem: 'p',
            publicKey: 'x',
            vaultId: 'v',
        });
        expect(typeof plugin).toBe('function');

        // Fordefi native manual mode modifies but does not broadcast, so Kit can
        // run it as a client payer.
        const manualConfig = {
            accessToken: 't',
            backend: 'fordefi',
            chain: 'solana_mainnet',
            privateKeyPem: 'p',
            publicKey: 'x',
            pushMode: 'manual',
            vaultId: 'v',
        } as const;
        const manualPlugin = keychainPayer(manualConfig);
        expect(typeof manualPlugin).toBe('function');

        // As an identity-only signer it could never be the fee payer, so the
        // config is rejected at the type level too.
        // @ts-expect-error Fordefi native manual mode cannot serve as identity alone
        keychainIdentity(manualConfig);
    });
});

describe('composition', () => {
    it('allows separate payer and identity signers on one client', async () => {
        const otherSeed = new Uint8Array(32).fill(9);
        const client = await createClient()
            .use(keychainPayer(MEMORY_CONFIG))
            .use(keychainIdentity({ backend: 'memory', privateKey: otherSeed }));

        expect(client.payer.address).not.toBe(client.identity.address);
    });

    it('propagates signer construction failures', async () => {
        await expect(
            createClient().use(keychainSigner({ backend: 'memory', privateKey: new Uint8Array(5) })),
        ).rejects.toThrow();
    });
});
