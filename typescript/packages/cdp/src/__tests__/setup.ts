import type { SolanaMessageSigner, SolanaTransactionSigner } from '@solana/keychain-core';
import type { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';

import { createCdpSigner } from '../cdp-signer.js';

const SIGNER_TYPE = 'cdp';
const REQUIRED_ENV_VARS = ['CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET', 'CDP_SOLANA_ADDRESS'];

const CONFIG: SignerTestConfig<SolanaMessageSigner & SolanaTransactionSigner> = {
    createSigner: () =>
        createCdpSigner({
            cdpApiKeyId: process.env.CDP_API_KEY_ID!,
            cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
            cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
            address: process.env.CDP_SOLANA_ADDRESS!,
        }),
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
