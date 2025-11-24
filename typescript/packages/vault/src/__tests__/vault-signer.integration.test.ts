import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana-keychain/test-utils';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

describe('VaultSigner Integration', () => {
    it.skipIf(!process.env.VAULT_ADDR)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.VAULT_ADDR)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.VAULT_ADDR)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
