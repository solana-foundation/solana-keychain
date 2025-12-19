import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { TurnkeySigner } from '../turnkey-signer';

const SIGNER_TYPE = 'turnkey';
const REQUIRED_ENV_VARS = [
    'TURNKEY_API_PUBLIC_KEY',
    'TURNKEY_API_PRIVATE_KEY',
    'TURNKEY_ORGANIZATION_ID',
    'TURNKEY_PRIVATE_KEY_ID',
    'TURNKEY_PUBLIC_KEY',
];

async function createTurnkeySigner(): Promise<TurnkeySigner> {
    return new TurnkeySigner({
        apiPublicKey: process.env.TURNKEY_API_PUBLIC_KEY!,
        apiPrivateKey: process.env.TURNKEY_API_PRIVATE_KEY!,
        organizationId: process.env.TURNKEY_ORGANIZATION_ID!,
        privateKeyId: process.env.TURNKEY_PRIVATE_KEY_ID!,
        publicKey: process.env.TURNKEY_PUBLIC_KEY!,
    });
}
const CONFIG: SignerTestConfig<TurnkeySigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: createTurnkeySigner,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<TurnkeySigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
