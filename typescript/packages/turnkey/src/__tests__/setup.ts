import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createTurnkeySigner } from '../turnkey-signer';

const SIGNER_TYPE = 'turnkey';
const REQUIRED_ENV_VARS = [
    'TURNKEY_API_PUBLIC_KEY',
    'TURNKEY_API_PRIVATE_KEY',
    'TURNKEY_ORGANIZATION_ID',
    'TURNKEY_PRIVATE_KEY_ID',
    'TURNKEY_PUBLIC_KEY',
];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        Promise.resolve(
            createTurnkeySigner({
                apiPublicKey: process.env.TURNKEY_API_PUBLIC_KEY!,
                apiPrivateKey: process.env.TURNKEY_API_PRIVATE_KEY!,
                organizationId: process.env.TURNKEY_ORGANIZATION_ID!,
                privateKeyId: process.env.TURNKEY_PRIVATE_KEY_ID!,
                publicKey: process.env.TURNKEY_PUBLIC_KEY!,
            }),
        ),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
