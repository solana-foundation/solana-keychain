import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';
import { describe, it } from 'vitest';

import { getConfig } from './setup';

config();

describe('OpenfortSigner Integration', () => {
    it.skipIf(!process.env.OPENFORT_SECRET_KEY)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.OPENFORT_SECRET_KEY)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.OPENFORT_SECRET_KEY)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
