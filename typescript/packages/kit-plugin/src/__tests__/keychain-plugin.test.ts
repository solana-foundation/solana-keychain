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
