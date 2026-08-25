import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createFordefiSigner } from '../fordefi-signer';

const SIGNER_TYPE = 'fordefi';
// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so poll well beyond the defaults.
const MAX_POLL_ATTEMPTS = 110;
const POLL_INTERVAL_MS = 1000;
// LiteSVM integration tests use the black_box signing path (raw bytes, no
// transaction modification). This requires a Fordefi black_box vault.
// Set FORDEFI_BB_VAULT_ID and FORDEFI_BB_PUBLIC_KEY for the BB vault.
const REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_BB_VAULT_ID',
    'FORDEFI_BB_PUBLIC_KEY',
    'FORDEFI_PRIVATE_KEY_PEM',
];

// Native manual signing needs a regular Fordefi Solana vault and an explicit
// chain: never default the chain, or a mainnet vault would submit against the
// wrong network.
export const MANUAL_REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_CHAIN',
    'FORDEFI_PRIVATE_KEY_PEM',
    'FORDEFI_PUBLIC_KEY',
    'FORDEFI_VAULT_ID',
];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createFordefiSigner({
            accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
            apiBaseUrl: process.env.FORDEFI_API_BASE_URL,
            maxPollAttempts: MAX_POLL_ATTEMPTS,
            pollIntervalMs: POLL_INTERVAL_MS,
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

export function hasManualEnv(): boolean {
    return MANUAL_REQUIRED_ENV_VARS.every(name => process.env[name]);
}

export function createManualSigner() {
    const chain = process.env.FORDEFI_CHAIN;
    if (chain !== 'solana_devnet' && chain !== 'solana_mainnet') {
        throw new Error("FORDEFI_CHAIN must be 'solana_devnet' or 'solana_mainnet'");
    }
    return createFordefiSigner({
        accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
        apiBaseUrl: process.env.FORDEFI_API_BASE_URL,
        chain,
        maxPollAttempts: MAX_POLL_ATTEMPTS,
        pollIntervalMs: POLL_INTERVAL_MS,
        privateKeyPem: process.env.FORDEFI_PRIVATE_KEY_PEM!,
        publicKey: process.env.FORDEFI_PUBLIC_KEY!,
        pushMode: 'manual',
        vaultId: process.env.FORDEFI_VAULT_ID!,
    });
}
