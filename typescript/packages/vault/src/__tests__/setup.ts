import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createVaultSigner } from '../vault-signer';

const SIGNER_TYPE = 'vault';
const REQUIRED_ENV_VARS = ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_KEY_NAME', 'VAULT_SIGNER_PUBKEY'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        Promise.resolve(
            createVaultSigner({
                vaultAddr: process.env.VAULT_ADDR!,
                vaultToken: process.env.VAULT_TOKEN!,
                keyName: process.env.VAULT_KEY_NAME!,
                publicKey: process.env.VAULT_SIGNER_PUBKEY!,
            }),
        ),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
