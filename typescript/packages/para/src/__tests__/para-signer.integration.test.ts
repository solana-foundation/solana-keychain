import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

describe('ParaSigner Integration', () => {
    it.skipIf(!process.env.PARA_API_KEY)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.PARA_API_KEY)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.PARA_API_KEY)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
