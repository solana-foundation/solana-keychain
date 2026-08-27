import type { SolanaMessageSigner, SolanaTransactionSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';

import { createOpenfortSigner } from '../openfort-signer.js';

const SIGNER_TYPE = 'openfort';
const REQUIRED_ENV_VARS = ['OPENFORT_SECRET_KEY', 'OPENFORT_ACCOUNT_ID', 'OPENFORT_WALLET_SECRET'];

const CONFIG: SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createOpenfortSigner({
            accountId: process.env.OPENFORT_ACCOUNT_ID!,
            baseUrl: process.env.OPENFORT_BASE_URL,
            secretKey: process.env.OPENFORT_SECRET_KEY!,
            walletSecret: process.env.OPENFORT_WALLET_SECRET!,
        }),
};

export async function getConfig(
    scenarios: TestScenario[],
): Promise<SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
