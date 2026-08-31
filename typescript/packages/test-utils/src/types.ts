import type { Address, MessagePartialSigner, TransactionSigner } from '@solana/kit';

import type { LiteSVM } from './litesvm-helpers.js';

export interface SignerTestConfig<T extends TestSigner> {
    createSigner: () => Promise<T>;

    /** Optional recipient address for testing (defaults to random address) */
    recipientAddress?: Address;

    requiredEnvVars: string[];

    signerType: string;

    /** Optional test scenarios to run (defaults to all) */
    testScenarios?: TestScenario[];
}

export type TestScenario = 'badSignature' | 'signMessage' | 'signTransaction' | 'simulateTransaction';

export interface TestOptions {
    /** Custom airdrop amount in lamports (default: 1_000_000_000) */
    airdropAmount?: bigint;

    /** Custom transfer amount in lamports (default: 100_000_000) */
    transferAmount?: bigint;

    /** Whether to log verbose output (default: false) */
    verbose?: boolean;
}

export interface TestResult {
    scenarios: {
        error?: Error;
        name: TestScenario;
        passed: boolean;
    }[];
    success: boolean;
}

export type TestSigner = Partial<MessagePartialSigner> & TransactionSigner;

export interface TestContext<T extends TestSigner> {
    litesvm: LiteSVM;
    options: Required<TestOptions>;
    recipientAddress: Address;
    signer: T;
}
