import type { SignatureBytes, SignaturesMap } from '@solana/kit';
import {
    appendTransactionMessageInstructions,
    createSignableMessage,
    createTransactionMessage,
    generateKeyPairSigner,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';

import { airdropLamports, formatSimulationResult, LiteSVM, truncateAddress } from './litesvm-helpers.js';
import type { SignerTestConfig, TestContext, TestOptions, TestScenario, TestSigner } from './types.js';

const DEFAULT_AIRDROP = BigInt(1_000_000_000);
const DEFAULT_TRANSFER = BigInt(100_000_000);

const DEFAULT_OPTIONS: Required<TestOptions> = {
    airdropAmount: DEFAULT_AIRDROP,
    transferAmount: DEFAULT_TRANSFER,
    verbose: false,
};
const AIRDROP_FEE_BUFFER = BigInt(50_000);

const ALL_SCENARIOS: TestScenario[] = ['signTransaction', 'signMessage', 'simulateTransaction', 'badSignature'];

/**
 * Main entry point for running integration tests
 * Use this in your test files with your test framework's assertions
 *
 * @param config - Test configuration including signer factory and env vars
 * @param litesvm - LiteSVM instance (must be provided by consuming project)
 * @param options - Optional test configuration
 */
export async function runSignerIntegrationTest<T extends TestSigner>(
    config: SignerTestConfig<T>,
    options: TestOptions = {},
): Promise<void> {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const airdropSourceLamports = opts.airdropAmount + AIRDROP_FEE_BUFFER;

    // Validate environment
    validateEnvironment(config.requiredEnvVars);

    // Create LiteSVM instance with minimal setup to avoid OOM on constrained CI runners.
    // The full constructor loads SPL programs which require significantly more memory.
    const litesvm = LiteSVM.default()
        .withLamports(airdropSourceLamports)
        .withSysvars()
        .withBuiltins()
        .withSigverify(true)
        .withPrecompiles();

    // Create signer
    const signer = await config.createSigner();

    if (opts.verbose) {
        console.log(`Testing ${config.signerType} signer`);
        console.log(`Address: ${truncateAddress(signer.address)}`);
    }

    // Setup test environment
    const recipientAddress = config.recipientAddress ?? (await generateKeyPairSigner()).address;

    airdropLamports(litesvm, signer.address, opts.airdropAmount);
    airdropLamports(litesvm, recipientAddress, BigInt(1));

    const context: TestContext<T> = {
        litesvm,
        options: opts,
        recipientAddress,
        signer,
    };

    // Run test scenarios
    const scenarios = config.testScenarios ?? ALL_SCENARIOS;

    for (const scenario of scenarios) {
        await runScenario(scenario, context);
    }
}

/**
 * Validates that required environment variables are present
 */
function validateEnvironment(requiredVars: string[]): void {
    const missing = requiredVars.filter(v => !process.env[v]);

    if (missing.length > 0) {
        throw new Error(
            `Missing required environment variables: ${missing.join(', ')}\n` +
                'Please ensure your .env file is configured correctly.',
        );
    }
}

/**
 * Runs a specific test scenario
 */
async function runScenario<T extends TestSigner>(scenario: TestScenario, context: TestContext<T>): Promise<void> {
    switch (scenario) {
        case 'signTransaction':
            await testSignTransaction(context);
            break;
        case 'signMessage':
            await testSignMessage(context);
            break;
        case 'simulateTransaction':
            await testSimulateTransaction(context);
            break;
        case 'badSignature':
            await testBadSignature(context);
            break;
        default:
            throw new Error(`Unknown test scenario: ${scenario as string}`);
    }
}

/**
 * Test: Sign a transaction and verify it can be simulated successfully
 */
async function testSignTransaction<T extends TestSigner>(context: TestContext<T>): Promise<void> {
    const { signer, litesvm, options, recipientAddress } = context;

    if (options.verbose) {
        console.log('Testing transaction signing...');
    }

    const instruction = getTransferSolInstruction({
        amount: options.transferAmount,
        destination: recipientAddress,
        source: signer,
    });
    litesvm.expireBlockhash();
    const blockhash = litesvm.latestBlockhash();

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    );

    const signedTransaction = await signTransactionMessageWithSigners(transaction);

    // Verify transaction has signatures
    if (!signedTransaction.signatures || Object.keys(signedTransaction.signatures).length === 0) {
        throw new Error('Transaction was not signed - no signatures present');
    }

    // Verify signer's signature is present
    if (!signedTransaction.signatures[signer.address]) {
        throw new Error(`Missing signature for signer address ${signer.address}`);
    }

    const result = litesvm.simulateTransaction(signedTransaction);
    const formatted = formatSimulationResult(result);

    if (!formatted.success) {
        throw new Error(`Transaction simulation failed: ${formatted?.error?.toString()}`);
    }

    if (options.verbose) {
        console.log('✓ Transaction signed and simulated successfully');
        console.log(`  Compute units: ${formatted.computeUnits}`);
    }
}

/**
 * Test: Sign a message and verify the signature is valid
 */
async function testSignMessage<T extends TestSigner>(context: TestContext<T>): Promise<void> {
    const { signer, options } = context;

    if (options.verbose) {
        console.log('Testing message signing...');
    }

    const messageContent = new Uint8Array([1, 2, 3, 4, 5]);
    const message = createSignableMessage(messageContent);

    const [signatureDict] = await signer.signMessages([message]);

    if (!signatureDict) {
        throw new Error('No signature dictionary returned from signMessages');
    }

    const signature = signatureDict[signer.address];

    if (!signature) {
        throw new Error(`Missing signature for signer address ${signer.address}`);
    }

    if (signature.length !== 64) {
        throw new Error(`Invalid signature length: expected 64, got ${signature.length}`);
    }

    if (options.verbose) {
        console.log('✓ Message signed successfully');
    }
}

/**
 * Test: Simulate a transaction without actually sending it
 */
async function testSimulateTransaction<T extends TestSigner>(context: TestContext<T>): Promise<void> {
    const { signer, litesvm, options, recipientAddress } = context;

    if (options.verbose) {
        console.log('Testing transaction simulation...');
    }

    const instruction = getTransferSolInstruction({
        amount: options.transferAmount,
        destination: recipientAddress,
        source: signer,
    });
    litesvm.expireBlockhash();
    const blockhash = litesvm.latestBlockhash();

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    );

    const signedTransaction = await signTransactionMessageWithSigners(transaction);
    const result = litesvm.simulateTransaction(signedTransaction);
    const formatted = formatSimulationResult(result);

    if (!formatted.success) {
        throw new Error(`Simulation failed: ${formatted?.error?.toString()}`);
    }

    if (!formatted.logs || formatted.logs.length === 0) {
        throw new Error('Simulation returned no logs');
    }

    if (options.verbose) {
        console.log('✓ Transaction simulated successfully');
        console.log(`  Logs: ${formatted.logs.length} entries`);
    }
}

/**
 * Test: Verify that a transaction with a bad signature fails validation
 */
async function testBadSignature<T extends TestSigner>(context: TestContext<T>): Promise<void> {
    const { signer, litesvm, options, recipientAddress } = context;

    if (options.verbose) {
        console.log('Testing bad signature detection...');
    }

    const instruction = getTransferSolInstruction({
        amount: options.transferAmount,
        destination: recipientAddress,
        source: signer,
    });
    litesvm.expireBlockhash();
    const blockhash = litesvm.latestBlockhash();

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    );

    const signedTransaction = await signTransactionMessageWithSigners(transaction);

    // Replace with a known bad signature
    const badSignature: SignaturesMap = {
        [signer.address]: new Uint8Array([
            214, 77, 129, 89, 164, 235, 121, 219, 146, 31, 168, 106, 229, 87, 42, 167, 124, 94, 122, 181, 174, 123, 29,
            95, 69, 244, 66, 206, 236, 229, 39, 183, 32, 66, 203, 230, 230, 63, 43, 246, 201, 198, 147, 22, 57, 232,
            200, 30, 17, 30, 243, 204, 58, 89, 57, 73, 23, 169, 174, 240, 237, 69, 82, 7,
        ]) as SignatureBytes,
    };

    const badTransaction = {
        ...signedTransaction,
        signatures: badSignature,
    };

    const result = litesvm.simulateTransaction(badTransaction);
    const formatted = formatSimulationResult(result);

    // Bad signature should cause failure
    if (formatted.success) {
        throw new Error('Expected transaction with bad signature to fail, but it succeeded');
    }

    if (options.verbose) {
        console.log('✓ Bad signature correctly rejected');
        console.log(`  Error: ${formatted?.error?.toString()}`);
    }
}
