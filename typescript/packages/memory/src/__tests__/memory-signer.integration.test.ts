import { runSignerIntegrationTest, type SignerTestConfig } from '@solana/keychain-test-utils';
import type { SolanaMessageSigner, SolanaTransactionSigner } from '@solana/keychain-core';
import { generateKeyPair } from '@solana/keys';
import { describe, it } from 'vitest';

import { createMemorySignerFromKeyPair } from '../memory-signer.js';

const CONFIG: SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner> = {
    signerType: 'memory',
    requiredEnvVars: [],
    createSigner: async () => createMemorySignerFromKeyPair(await generateKeyPair()),
};

describe('memory signer integration', () => {
    it('signs transactions on LiteSVM', async () => {
        await runSignerIntegrationTest({ ...CONFIG, testScenarios: ['signTransaction'] });
    });

    it('signs messages on LiteSVM', async () => {
        await runSignerIntegrationTest({ ...CONFIG, testScenarios: ['signMessage'] });
    });

    it('simulates transactions on LiteSVM', async () => {
        await runSignerIntegrationTest({ ...CONFIG, testScenarios: ['simulateTransaction'] });
    });

    it('rejects bad signatures on LiteSVM', async () => {
        await runSignerIntegrationTest({ ...CONFIG, testScenarios: ['badSignature'] });
    });
});
