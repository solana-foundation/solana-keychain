import type { TestScenario } from '@solana/keychain-test-utils';
import type { SolanaSendingSigner } from '@solana/keychain-core';
import { createCrossmintSigner } from '../crossmint-signer.js';

const SIGNER_TYPE = 'crossmint';
const REQUIRED_ENV_VARS = ['CROSSMINT_API_KEY', 'CROSSMINT_WALLET_LOCATOR'];

// Crossmint is a sending signer with no partial-signer methods, so its config
// does not satisfy `SignerTestConfig` and the shared LiteSVM runner does not
// apply; the integration test drives the signer directly.
interface CrossmintTestConfig {
    createSigner: () => Promise<SolanaSendingSigner>;
    requiredEnvVars: string[];
    signerType: string;
    testScenarios?: TestScenario[];
}

const CONFIG: CrossmintTestConfig = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: async () =>
        await createCrossmintSigner({
            apiKey: process.env.CROSSMINT_API_KEY!,
            walletLocator: process.env.CROSSMINT_WALLET_LOCATOR!,
            apiBaseUrl: process.env.CROSSMINT_API_BASE_URL,
            maxPollAttempts: process.env.CROSSMINT_MAX_POLL_ATTEMPTS
                ? Number(process.env.CROSSMINT_MAX_POLL_ATTEMPTS)
                : undefined,
            pollIntervalMs: process.env.CROSSMINT_POLL_INTERVAL_MS
                ? Number(process.env.CROSSMINT_POLL_INTERVAL_MS)
                : undefined,
            signerSecret: process.env.CROSSMINT_SIGNER_SECRET,
            signer: process.env.CROSSMINT_SIGNER,
        }),
};

export async function getConfig(scenarios: TestScenario[]): Promise<CrossmintTestConfig> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
