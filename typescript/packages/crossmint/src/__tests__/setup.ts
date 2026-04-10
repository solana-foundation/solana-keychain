import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createCrossmintSigner } from '../crossmint-signer.js';

const SIGNER_TYPE = 'crossmint';
const REQUIRED_ENV_VARS = ['CROSSMINT_API_KEY', 'CROSSMINT_WALLET_LOCATOR'];
const TEST_SIGNER_DERIVED_PUBKEY_ENV = 'TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY';

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: async () => {
        const signer = await createCrossmintSigner({
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
        });

        // Test-only override for environments where Crossmint's returned wallet
        // pubkey differs from the signer key used in signed transaction bytes.
        const testSignerDerivedPubkey = resolveTestSignerDerivedPubkey();
        if (testSignerDerivedPubkey) {
            (signer as { address: string }).address = testSignerDerivedPubkey;
        }

        return signer;
    },
};

function resolveTestSignerDerivedPubkey(): string | undefined {
    const explicit = process.env[TEST_SIGNER_DERIVED_PUBKEY_ENV]?.trim();
    if (explicit) return explicit;

    const configuredSigner = process.env.CROSSMINT_SIGNER?.trim();
    if (!configuredSigner?.startsWith('server:')) return undefined;

    const derived = configuredSigner.slice('server:'.length).trim();
    return derived || undefined;
}

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
