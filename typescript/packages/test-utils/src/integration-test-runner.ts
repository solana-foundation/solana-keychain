import { ED25519_SIGNATURE_LENGTH } from '@solana/keychain-core';
import type { SignatureBytes, SignaturesMap } from '@solana/kit';
import {
    appendTransactionMessageInstructions,
    createSignableMessage,
    createTransactionMessage,
    generateKeyPairSigner,
    pipe,
    setTransactionMessageFeePayerSigner,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import { LiteSVM } from 'litesvm';

import { airdropLamports, formatSimulationResult, truncateAddress } from './litesvm-helpers.js';
import type { SignerTestConfig, TestContext, TestOptions, TestScenario, TestSigner } from './types.js';

const DEFAULT_AIRDROP = BigInt(1_000_000_000);
const DEFAULT_TRANSFER = BigInt(100_000_000);
// Conservative buffer (≥10× the ~890k rent-exempt minimum for a 0-byte account) so the faucet
// stays rent-exempt after the airdrop tx fee is taken.
const FAUCET_RESERVE = BigInt(10_000_000);

const DEFAULT_OPTIONS: Required<TestOptions> = {
    airdropAmount: DEFAULT_AIRDROP,
    transferAmount: DEFAULT_TRANSFER,
    verbose: false,
};

const ALL_SCENARIOS: TestScenario[] = ['signTransaction', 'signMessage', 'simulateTransaction', 'badSignature'];

/**
 * Main entry point for running integration tests
 * Use this in your test files with your test framework's assertions
 *
 * @param config - Test configuration including signer factory and env vars
 * @param options - Optional test configuration
 */
export async function runSignerIntegrationTest<T extends TestSigner>(
    config: SignerTestConfig<T>,
    options: TestOptions = {},
): Promise<void> {
    const opts = { ...DEFAULT_OPTIONS, ...options };

    validateEnvironment(config.requiredEnvVars);

    // Minimal SVM: sysvars + builtins + sigverify + precompiles. No SPL programs (unused) — keeps startup small.
    // The faucet pool is sized to the signer airdrop plus a reserve so the faucet stays rent-exempt after.
    const litesvm = LiteSVM.default()
        .withLamports(opts.airdropAmount + FAUCET_RESERVE)
        .withSysvars()
        .withBuiltins()
        .withSigverify(true)
        .withPrecompiles();

    const signer = await config.createSigner();

    if (opts.verbose) {
        console.log(`Testing ${config.signerType} signer`);
        console.log(`Address: ${truncateAddress(signer.address)}`);
    }

    // The recipient is funded by the test transfer itself, so only the signer
    // needs an airdrop here.
    const recipientAddress = config.recipientAddress ?? (await generateKeyPairSigner()).address;

    airdropLamports(litesvm, signer.address, opts.airdropAmount);

    const context: TestContext<T> = {
        litesvm,
        options: opts,
        recipientAddress,
        signer,
    };

    const scenarios = config.testScenarios ?? ALL_SCENARIOS;

    for (const scenario of scenarios) {
        await runScenario(scenario, context);
    }
}

function validateEnvironment(requiredVars: string[]): void {
    const missing = requiredVars.filter(v => !process.env[v]);

    if (missing.length > 0) {
        throw new Error(
            `Missing required environment variables: ${missing.join(', ')}\n` +
                'Please ensure your .env file is configured correctly.',
        );
    }
}

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

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => litesvm.setTransactionMessageLifetimeUsingLatestBlockhash(tx),
    );

    const signedTransaction = await signTransactionMessageWithSigners(transaction);

    if (!signedTransaction.signatures || Object.keys(signedTransaction.signatures).length === 0) {
        throw new Error('Transaction was not signed - no signatures present');
    }

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

async function testSignMessage<T extends TestSigner>(context: TestContext<T>): Promise<void> {
    const { signer, options } = context;

    if (options.verbose) {
        console.log('Testing message signing...');
    }

    if (!signer.signMessages) {
        throw new Error('Signer exposes no signMessages; drop the signMessage scenario for this backend');
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

    if (signature.length !== ED25519_SIGNATURE_LENGTH) {
        throw new Error(`Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH}, got ${signature.length}`);
    }

    if (options.verbose) {
        console.log('✓ Message signed successfully');
    }
}

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

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => litesvm.setTransactionMessageLifetimeUsingLatestBlockhash(tx),
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

    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => litesvm.setTransactionMessageLifetimeUsingLatestBlockhash(tx),
    );

    const signedTransaction = await signTransactionMessageWithSigners(transaction);

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

    // Bad signature should cause failure. Sigverify is explicitly enabled at SVM construction,
    // so a successful simulation here means sigverify was bypassed — surface that loud.
    if (formatted.success) {
        throw new Error('Expected transaction with bad signature to fail, but it succeeded');
    }

    if (options.verbose) {
        console.log('✓ Bad signature correctly rejected');
        console.log(`  Error: ${formatted?.error?.toString()}`);
    }
}
