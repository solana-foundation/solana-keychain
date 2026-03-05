import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';
import { describe, it } from 'vitest';

import { getConfig } from './setup.js';

config();

describe('FireblocksSigner Integration', () => {
    it.skipIf(!process.env.FIREBLOCKS_API_KEY)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.FIREBLOCKS_API_KEY)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.FIREBLOCKS_API_KEY)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
