import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';
import { describe, it } from 'vitest';

import { getConfig } from './setup.js';

config();

describe('CdpSigner Integration', () => {
    it.skipIf(!process.env.CDP_API_KEY_ID)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.CDP_API_KEY_ID)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.CDP_API_KEY_ID)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
