import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createFordefiSigner } from '../fordefi-signer';

const SIGNER_TYPE = 'fordefi';
// LiteSVM integration tests use the black_box signing path (raw bytes, no
// transaction modification). This requires a Fordefi black_box vault.
// Set FORDEFI_BB_VAULT_ID and FORDEFI_BB_PUBLIC_KEY for the BB vault.
const REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_BB_VAULT_ID',
    'FORDEFI_BB_PUBLIC_KEY',
    'FORDEFI_PRIVATE_KEY_PEM',
];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createFordefiSigner({
            accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
            apiBaseUrl: process.env.FORDEFI_API_BASE_URL,
            maxPollAttempts: 110,
            pollIntervalMs: 1000,
            privateKeyPem: process.env.FORDEFI_PRIVATE_KEY_PEM!,
            publicKey: process.env.FORDEFI_BB_PUBLIC_KEY!,
            vaultId: process.env.FORDEFI_BB_VAULT_ID!,
        }),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
