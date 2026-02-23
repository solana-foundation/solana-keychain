import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { ParaSigner } from '../para-signer';

const SIGNER_TYPE = 'para';
const REQUIRED_ENV_VARS = ['PARA_API_KEY', 'PARA_WALLET_ID'];

async function createParaSigner(): Promise<ParaSigner> {
    return await ParaSigner.create({
        apiKey: process.env.PARA_API_KEY!,
        apiBaseUrl: process.env.PARA_API_BASE_URL,
        walletId: process.env.PARA_WALLET_ID!,
    });
}
const CONFIG: SignerTestConfig<ParaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: createParaSigner,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<ParaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
