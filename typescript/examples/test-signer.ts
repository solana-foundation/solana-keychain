/**
 * Manual test script for Solana signers with real API credentials
 *
 * Supports multiple signer types via SIGNER_TYPE env var:
 *   - fireblocks
 *   - privy
 *   - turnkey
 *   - keypair
 *
 * Usage:
 *   1. Copy .env.example to .env and fill in credentials for your signer
 *   2. SIGNER_TYPE=fireblocks pnpm test:signer
 *   3. SIGNER_TYPE=privy pnpm test:signer
 *   4. SIGNER_TYPE=turnkey pnpm test:signer
 *   5. SIGNER_TYPE=keypair pnpm test:signer
 *
 * Example AWS KMS args (Rust only):
 *   - AWS_KMS_KEY_ID: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
 *   - AWS_KMS_PUBLIC_KEY: "YourSolanaPublicKeyBase58Here"
 *   - AWS_KMS_REGION: "us-east-1" (optional, defaults to AWS config default region)
 */

import { assertIsSolanaSigner, SolanaSigner } from '@solana-keychain/core';
import { FireblocksSigner } from '@solana-keychain/fireblocks';
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
    assertIsKeyPairSigner,
} from '@solana/kit';
import { getAddMemoInstruction } from '@solana-program/memo';
import * as dotenv from 'dotenv';

dotenv.config({ path: './.env' });

type SignerType = 'fireblocks' | 'privy' | 'turnkey' | 'keypair';

function getSignerType(): SignerType {
    const signerEnv = process.env.SIGNER_TYPE;
    if (!signerEnv) {
        throw new Error('SIGNER_TYPE is not set');
    }
    const signerType = signerEnv.toLowerCase() as SignerType;
    if (signerType !== 'fireblocks' && signerType !== 'privy' && signerType !== 'turnkey' && signerType !== 'keypair') {
        throw new Error(`Invalid signer type: ${signerType}`);
    }
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
    fireblocks: {
        requiredEnvVars: ['FIREBLOCKS_API_KEY', 'FIREBLOCKS_PRIVATE_KEY_PEM', 'FIREBLOCKS_VAULT_ACCOUNT_ID'],
        create: async () => {
            const signer = new FireblocksSigner({
                apiKey: process.env.FIREBLOCKS_API_KEY!,
                privateKeyPem: process.env.FIREBLOCKS_PRIVATE_KEY_PEM!,
                vaultAccountId: process.env.FIREBLOCKS_VAULT_ACCOUNT_ID!,
                assetId: 'SOL_TEST',
                apiBaseUrl: 'https://api.fireblocks.io',
            });
            await signer.init();
            return signer;
        },
    },
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
    // Example AWS KMS args (Rust only - not yet implemented in TypeScript):
    // aws_kms: {
    //     requiredEnvVars: ['AWS_KMS_KEY_ID', 'AWS_KMS_PUBLIC_KEY'],
    //     create: async () => {
    //         // AWS KMS signer implementation would go here
    //         // Example args:
    //         //   key_id: process.env.AWS_KMS_KEY_ID! // e.g., "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    //         //   public_key: process.env.AWS_KMS_PUBLIC_KEY! // Solana public key (base58-encoded)
    //         //   region: process.env.AWS_KMS_REGION // Optional AWS region
    //         throw new Error('AWS KMS signer not yet implemented in TypeScript');
    //     },
    // },
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
        console.error(
            `Missing required environment variables for ${signerType}: ${missing.forEach(v => console.error(`\n  ✗ ${v}`))}`,
        );
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
    address,
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
