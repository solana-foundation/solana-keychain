import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

describe('DfnsSigner Integration', () => {
    it.skipIf(!process.env.DFNS_AUTH_TOKEN)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.DFNS_AUTH_TOKEN)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.DFNS_AUTH_TOKEN)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
