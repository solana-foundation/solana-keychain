import { SignerTestConfig, TestScenario } from '@solana-keychain/test-utils';
import { PrivySigner } from '../privy-signer';

const SIGNER_TYPE = 'privy';
const REQUIRED_ENV_VARS = ['PRIVY_APP_ID', 'PRIVY_APP_SECRET', 'PRIVY_WALLET_ID'];

async function createPrivySigner(): Promise<PrivySigner> {
    return await PrivySigner.create({
        appId: process.env.PRIVY_APP_ID!,
        appSecret: process.env.PRIVY_APP_SECRET!,
        walletId: process.env.PRIVY_WALLET_ID!,
    });
}
const CONFIG: SignerTestConfig<PrivySigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: createPrivySigner,
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<PrivySigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
