import { describe, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so we extend the per-test timeout well beyond the
// vitest default of 30s.
const TEST_TIMEOUT_MS = 120_000;

describe('FordefiSigner Integration', () => {
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signTransaction']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs messages with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signMessage']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'simulates transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
        },
        TEST_TIMEOUT_MS,
    );
});
