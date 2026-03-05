import type { SolanaSigner } from '@solana/keychain-core';
import type { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';

import { createAwsKmsSigner } from '../aws-kms-signer.js';

export const TEST_KEY_ID = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
export const TEST_REGION = 'us-east-1';

const SIGNER_TYPE = 'aws-kms';
const REQUIRED_ENV_VARS = ['AWS_KMS_KEY_ID', 'AWS_KMS_SIGNER_PUBKEY'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    createSigner: () =>
        Promise.resolve(
            createAwsKmsSigner({
                keyId: process.env.AWS_KMS_KEY_ID!,
                publicKey: process.env.AWS_KMS_SIGNER_PUBKEY!,
                region: process.env.AWS_KMS_REGION,
            }),
        ),
    requiredEnvVars: REQUIRED_ENV_VARS,
    signerType: SIGNER_TYPE,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
