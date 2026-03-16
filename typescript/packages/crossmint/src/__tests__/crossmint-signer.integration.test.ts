import { createSignableMessage } from '@solana/kit';
import { describe, expect, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

describe('CrossmintSigner Integration', () => {
    it.skipIf(!process.env.CROSSMINT_API_KEY)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });

    it.skipIf(!process.env.CROSSMINT_API_KEY)('returns not supported for signMessages', async () => {
        const { createSigner } = await getConfig(['signMessage']);
        const signer = await createSigner();
        const message = createSignableMessage(new Uint8Array([1, 2, 3]));
        await expect(signer.signMessages([message])).rejects.toThrow('not supported');
    });

    it.skipIf(!process.env.CROSSMINT_API_KEY)('checks availability', async () => {
        const { createSigner } = await getConfig([]);
        const signer = await createSigner();
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
