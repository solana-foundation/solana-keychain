import type { SolanaMessageSigner, SolanaTransactionSigner } from '@solana/keychain-core';
import type { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';

import { createGcpKmsSigner } from '../gcp-kms-signer.js';

const SIGNER_TYPE = 'gcp-kms';
const REQUIRED_ENV_VARS = ['GCP_KMS_KEY_NAME', 'GCP_KMS_SIGNER_PUBKEY'];

const CONFIG: SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner> = {
    createSigner: () =>
        Promise.resolve(
            createGcpKmsSigner({
                keyName: process.env.GCP_KMS_KEY_NAME!,
                publicKey: process.env.GCP_KMS_SIGNER_PUBKEY!,
            }),
        ),
    requiredEnvVars: REQUIRED_ENV_VARS,
    signerType: SIGNER_TYPE,
};

export async function getConfig(
    scenarios: TestScenario[],
): Promise<SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
