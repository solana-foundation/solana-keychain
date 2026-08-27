import type { SolanaMessageSigner, SolanaTransactionSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createParaSigner } from '../para-signer';

const SIGNER_TYPE = 'para';
const REQUIRED_ENV_VARS = ['PARA_API_KEY', 'PARA_WALLET_ID'];

const CONFIG: SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createParaSigner({
            apiKey: process.env.PARA_API_KEY!,
            apiBaseUrl: process.env.PARA_API_BASE_URL,
            walletId: process.env.PARA_WALLET_ID!,
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
