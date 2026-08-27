import type { Address, MessagePartialSigner, TransactionSigner } from '@solana/kit';

import type { LiteSVM } from './litesvm-helpers.js';

/**
 * Configuration for running a signer integration test
 */
export interface SignerTestConfig<T extends TestSigner> {
    /** Factory function to create the signer instance */
    createSigner: () => Promise<T>;

    /** Optional recipient address for testing (defaults to random address) */
    recipientAddress?: Address;

    /** Required environment variables for this test */
    requiredEnvVars: string[];

    /** Descriptive name for the signer type */
    signerType: string;

    /** Optional test scenarios to run (defaults to all) */
    testScenarios?: TestScenario[];
}

/**
 * Available test scenarios
 */
export type TestScenario = 'badSignature' | 'signMessage' | 'signTransaction' | 'simulateTransaction';

/**
 * Options for configuring test behavior
 */
export interface TestOptions {
    /** Custom airdrop amount in lamports (default: 1_000_000_000) */
    airdropAmount?: bigint;

    /** Custom transfer amount in lamports (default: 100_000_000) */
    transferAmount?: bigint;

    /** Whether to log verbose output (default: false) */
    verbose?: boolean;
}

/**
 * Result from running integration tests
 */
export interface TestResult {
    scenarios: {
        error?: Error;
        name: TestScenario;
        passed: boolean;
    }[];
    success: boolean;
}

export type TestSigner = Partial<MessagePartialSigner> & TransactionSigner;

/**
 * Context passed to test scenario functions
 */
export interface TestContext<T extends TestSigner> {
    litesvm: LiteSVM;
    options: Required<TestOptions>;
    recipientAddress: Address;
    signer: T;
}
