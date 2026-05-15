import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createPrivySigner } from '../privy-signer';

const SIGNER_TYPE = 'privy';
const REQUIRED_ENV_VARS = ['PRIVY_APP_ID', 'PRIVY_APP_SECRET', 'PRIVY_WALLET_ID'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createPrivySigner({
            ...(process.env.PRIVY_API_BASE_URL ? { apiBaseUrl: process.env.PRIVY_API_BASE_URL } : {}),
            appId: process.env.PRIVY_APP_ID!,
            appSecret: process.env.PRIVY_APP_SECRET!,
            walletId: process.env.PRIVY_WALLET_ID!,
            ...(process.env.PRIVY_AUTHORIZATION_PRIVATE_KEY
                ? {
                      authorizationContext: {
                          authorization_private_keys: [process.env.PRIVY_AUTHORIZATION_PRIVATE_KEY],
                      },
                  }
                : {}),
        }),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
