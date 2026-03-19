import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createCrossmintSigner } from '../crossmint-signer.js';

const SIGNER_TYPE = 'crossmint';
const REQUIRED_ENV_VARS = ['CROSSMINT_API_KEY', 'CROSSMINT_WALLET_LOCATOR'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createCrossmintSigner({
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

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
