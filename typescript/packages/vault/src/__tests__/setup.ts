import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { VaultSigner } from '../vault-signer';

const SIGNER_TYPE = 'vault';
const REQUIRED_ENV_VARS = ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_KEY_NAME', 'VAULT_SIGNER_PUBKEY'];

async function createVaultSigner(): Promise<VaultSigner> {
    return new VaultSigner({
        vaultAddr: process.env.VAULT_ADDR!,
        vaultToken: process.env.VAULT_TOKEN!,
        keyName: process.env.VAULT_KEY_NAME!,
        publicKey: process.env.VAULT_SIGNER_PUBKEY!,
    });
}
const CONFIG: SignerTestConfig<VaultSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: createVaultSigner,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<VaultSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
