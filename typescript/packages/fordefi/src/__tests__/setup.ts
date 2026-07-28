import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createFordefiSigner } from '../fordefi-signer';

export function resolvePemPath(raw: string): string {
    if (path.isAbsolute(raw)) return raw;
    const here = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(here, '..', '..', '..', '..', '..');
    return path.resolve(repoRoot, raw);
}

const SIGNER_TYPE = 'fordefi';
// LiteSVM integration tests use the black_box signing path (raw bytes, no
// transaction modification). This requires a Fordefi black_box vault.
// Set FORDEFI_BB_VAULT_ID and FORDEFI_BB_PUBLIC_KEY for the BB vault.
const REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_BB_VAULT_ID',
    'FORDEFI_BB_PUBLIC_KEY',
    'FORDEFI_PRIVATE_KEY_PEM_PATH',
];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createFordefiSigner({
            accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
            maxPollAttempts: 110,
            pollIntervalMs: 1000,
            privateKeyPem: fs.readFileSync(resolvePemPath(process.env.FORDEFI_PRIVATE_KEY_PEM_PATH!), 'utf8'),
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
