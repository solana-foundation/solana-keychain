/**
 * Manual test script for Solana signers with real API credentials
 * 
 * Supports multiple signer types via SIGNER_TYPE env var:
 *   - privy
 *   - turnkey
 *
 * Usage:
 *   1. Copy .env.example to .env and fill in credentials for your signer
 *   2. SIGNER_TYPE=privy pnpm test:signer
 *   3. SIGNER_TYPE=turnkey pnpm test:signer
 */

import { assertIsSolanaSigner, SolanaSigner } from '@solana-keychain/core';
import { PrivySigner } from '@solana-keychain/privy';
import { TurnkeySigner } from '@solana-keychain/turnkey';
import {
    Address,
    airdropFactory,
    appendTransactionMessageInstructions,
    createSolanaRpc,
    createSolanaRpcSubscriptions,
    createTransactionMessage,
    assertIsFullySignedTransaction,
    lamports,
    pipe,
    Rpc,
    RpcSubscriptions,
    RpcTransport,
    sendAndConfirmTransactionFactory,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
    SolanaRpcApiFromTransport,
    SolanaRpcSubscriptionsApi,
    assertIsTransactionWithBlockhashLifetime,
    getSignatureFromTransaction,
    generateKeyPairSigner,
    KeyPairSigner,
    assertIsKeyPairSigner
} from '@solana/kit';
import { getAddMemoInstruction } from '@solana-program/memo';
import * as dotenv from 'dotenv';

dotenv.config({ path: './.env' });

type SignerType = 'privy' | 'turnkey' | 'keypair';

function getSignerType(): SignerType {
    const signerEnv = process.env.SIGNER_TYPE;
    if (!signerEnv) { throw new Error('SIGNER_TYPE is not set') }
    const signerType = (signerEnv.toLowerCase()) as SignerType;
    if (signerType !== 'privy' && signerType !== 'turnkey' && signerType !== 'keypair') { throw new Error(`Invalid signer type: ${signerType}`) }
    return signerType;
}

function logStatus(step: number, message: string) {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`[${step}/6] ${message}`);
}

interface SignerConfig {
    requiredEnvVars: string[];
    create: () => Promise<SolanaSigner | KeyPairSigner>;
}

const SIGNER_CONFIGS: Record<SignerType, SignerConfig> = {
    privy: {
        requiredEnvVars: ['PRIVY_APP_ID', 'PRIVY_APP_SECRET', 'PRIVY_WALLET_ID'],
        create: async () => {
            return await PrivySigner.create({
                appId: process.env.PRIVY_APP_ID!,
                appSecret: process.env.PRIVY_APP_SECRET!,
                walletId: process.env.PRIVY_WALLET_ID!,
                apiBaseUrl: process.env.PRIVY_API_BASE_URL,
            });
        },
    },
    turnkey: {
        requiredEnvVars: [
            'TURNKEY_API_PUBLIC_KEY',
            'TURNKEY_API_PRIVATE_KEY',
            'TURNKEY_ORGANIZATION_ID',
            'TURNKEY_PRIVATE_KEY_ID',
            'TURNKEY_PUBLIC_KEY',
        ],
        create: async () => {
            return new TurnkeySigner({
                apiPublicKey: process.env.TURNKEY_API_PUBLIC_KEY!,
                apiPrivateKey: process.env.TURNKEY_API_PRIVATE_KEY!,
                organizationId: process.env.TURNKEY_ORGANIZATION_ID!,
                privateKeyId: process.env.TURNKEY_PRIVATE_KEY_ID!,
                publicKey: process.env.TURNKEY_PUBLIC_KEY!,
                apiBaseUrl: process.env.TURNKEY_API_BASE_URL,
            });
        },
    },
    keypair: {
        requiredEnvVars: [],
        create: async () => {
            return await generateKeyPairSigner();
        },
    },
};

function validateEnv(signerType: SignerType) {
    const config = SIGNER_CONFIGS[signerType];
    const missing = [...config.requiredEnvVars, 'SOLANA_RPC_URL', 'SOLANA_WS_URL'].filter(v => !process.env[v]);

    if (missing.length > 0) {
        console.error(`Missing required environment variables for ${signerType}: ${missing.forEach(v => console.error(`\n  ✗ ${v}`))}`);
        console.error('Please copy .env.example to .env and fill in your credentials');
        process.exit(1);
    }
}

async function createSigner(signerType: SignerType): Promise<SolanaSigner | KeyPairSigner> {
    const config = SIGNER_CONFIGS[signerType];
    return await config.create();
}

async function main() {
    const signerType = getSignerType();

    logStatus(1, `Validating environment for ${signerType}`);
    validateEnv(signerType);
    console.log('  ✓ Environment variables loaded');

    logStatus(2, `Creating ${signerType} signer`);

    const signer = await createSigner(signerType);

    const truncatedAddress = signer.address.slice(0, 4) + '...' + signer.address.slice(-4);
    console.log(`  ✓ Address: ${truncatedAddress}`);

    logStatus(3, `Checking signer availability`);

    try {
        if (signerType === 'keypair') {
            assertIsKeyPairSigner(signer as KeyPairSigner);
        } else {
            assertIsSolanaSigner(signer);
            const available = await signer.isAvailable();
            console.log(`  ✓ Available: ${available}`);

            if (!available) {
                console.error('  ✗ Signer is not available. Check your credentials.');
                process.exit(1);
            }
        }

    } catch (error) {
        console.error('  ✗ Error checking signer availability:', error);
        process.exit(1);
    }

    console.log('  ✓ Signer is available');
    const rpc = createSolanaRpc(process.env.SOLANA_RPC_URL!);
    const rpcSubscriptions = createSolanaRpcSubscriptions(process.env.SOLANA_WS_URL!);
    const sendAndConfirmTransaction = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });
    await handleAirdrop({ rpc, rpcSubscriptions, address: signer.address });

    logStatus(4, `Setting up transaction`);

    const instruction = getAddMemoInstruction({ memo: `Hello, ${signerType}` });

    const { value: blockhash } = await rpc.getLatestBlockhash().send();
    const transaction = pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(signer, tx),
        tx => appendTransactionMessageInstructions([instruction], tx),
        tx => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
    );
    console.log('  ✓ Transaction created');

    logStatus(5, `Signing transaction`);

    try {
        const signedTransaction = await signTransactionMessageWithSigners(transaction);
        const signatureAddresses = Object.keys(signedTransaction.signatures);
        const foundSignature = signatureAddresses.find(address => address === signer.address);
        console.log(`  ✓ Signature found: ${foundSignature ? 'Yes' : 'No'}`);

        if (!foundSignature) {
            console.error('  ✗ Signature not found for signer');
            process.exit(1);
        }

        logStatus(6, `Sending transaction`);

        assertIsFullySignedTransaction(signedTransaction);
        assertIsTransactionWithBlockhashLifetime(signedTransaction);
        await sendAndConfirmTransaction(signedTransaction, {
            commitment: 'processed',
            skipPreflight: true,
        });
        const signature = getSignatureFromTransaction(signedTransaction);

        console.log(`  ✓ Transaction sent: ${signature}`);
    } catch (error) {
        console.error('  ✗ Error signing transaction:', error);
        process.exit(1);
    }
}

async function handleAirdrop({
    rpc,
    rpcSubscriptions,
    address
}: {
    rpc: Rpc<SolanaRpcApiFromTransport<RpcTransport>>;
    rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
    address: Address;
}) {
    if (process.env.SOLANA_SKIP_AIRDROP === 'true') {
        console.log('  ✓ Skipping airdrop');
        return;
    }
    const airdrop = airdropFactory({ rpc, rpcSubscriptions });
    await airdrop({
        recipientAddress: address,
        lamports: lamports(1_000_000_000n),
        commitment: 'confirmed',
    });
    console.log('  ✓ Airdrop sent');
}

main().catch(error => {
    console.error('\n✗ Test failed:');
    console.error(error);
    process.exit(1);
});
