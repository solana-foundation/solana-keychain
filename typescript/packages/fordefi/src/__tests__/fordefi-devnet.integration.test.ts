/**
 * Fordefi devnet integration tests
 *
 * Tests native Solana mode (chain: 'solana_devnet') against the real Fordefi API.
 *
 * Required env vars:
 *   FORDEFI_ACCESS_TOKEN, FORDEFI_VAULT_ID, FORDEFI_PRIVATE_KEY_PEM_PATH,
 *   FORDEFI_PUBLIC_KEY
 *
 * Optional env vars:
 *   SOLANA_RPC_URL       — devnet RPC (default: https://api.devnet.solana.com)
 *   SOLANA_WS_URL        — devnet WS  (default: wss://api.devnet.solana.com)
 *   DEVNET_RECIPIENT     — recipient address (default: random keypair)
 */
import * as fs from 'node:fs';

import {
    address,
    appendTransactionMessageInstructions,
    assertIsFullySignedTransaction,
    assertIsTransactionWithBlockhashLifetime,
    createSolanaRpc,
    createSolanaRpcSubscriptions,
    createTransactionMessage,
    generateKeyPairSigner,
    getSignatureFromTransaction,
    lamports,
    pipe,
    sendAndConfirmTransactionFactory,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signAndSendTransactionMessageWithSigners,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import { createSignableMessage } from '@solana/signers';
import { config } from 'dotenv';
import { describe, expect, it } from 'vitest';

import { createFordefiSigner } from '../fordefi-signer.js';
import { resolvePemPath } from './setup.js';

config();

const REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_VAULT_ID',
    'FORDEFI_PRIVATE_KEY_PEM_PATH',
    'FORDEFI_PUBLIC_KEY',
];

// Black box devnet transfer uses the dedicated black box vault as the origin.
const BB_REQUIRED_ENV_VARS = [
    'FORDEFI_ACCESS_TOKEN',
    'FORDEFI_BB_VAULT_ID',
    'FORDEFI_BB_PUBLIC_KEY',
    'FORDEFI_PRIVATE_KEY_PEM_PATH',
    'FORDEFI_PUBLIC_KEY',
];

const TRANSFER_LAMPORTS = 100_000_000n; // 0.1 SOL
const TEST_TIMEOUT_MS = 180_000;

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

function hasBlackBoxEnvVars(): boolean {
    return BB_REQUIRED_ENV_VARS.every(v => process.env[v]);
}

describe('Fordefi Devnet Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'transfers 0.1 SOL on devnet via Fordefi native Solana signing',
        async () => {
            // 1. Create the Fordefi signer
            const signer = await createFordefiSigner({
                accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
                chain: 'solana_devnet',
                fee: { priority_fee: '1000', type: 'custom' },
                maxPollAttempts: 110,
                pollIntervalMs: 1000,
                privateKeyPem: fs.readFileSync(resolvePemPath(process.env.FORDEFI_PRIVATE_KEY_PEM_PATH!), 'utf8'),
                publicKey: process.env.FORDEFI_PUBLIC_KEY!,
                vaultId: process.env.FORDEFI_VAULT_ID!,
            });

            console.log(`Fordefi signer address: ${signer.address}`);

            // 2. Set up devnet RPC
            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';
            const rpc = createSolanaRpc(rpcUrl);

            // 3. Pick a recipient
            const recipient = process.env.DEVNET_RECIPIENT
                ? address(process.env.DEVNET_RECIPIENT)
                : (await generateKeyPairSigner()).address;
            console.log(`Recipient: ${recipient}`);

            // 4. Check signer balance
            const { value: balance } = await rpc.getBalance(signer.address).send();
            console.log(`Signer balance: ${balance} lamports`);
            const needed = TRANSFER_LAMPORTS + 10_000n; // transfer + fee headroom
            expect(balance >= needed).toBe(true);

            // 5. Build the transfer transaction
            const { value: blockhashInfo } = await rpc.getLatestBlockhash().send();
            const instruction = getTransferSolInstruction({
                amount: lamports(TRANSFER_LAMPORTS),
                destination: recipient,
                source: signer,
            });

            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([instruction], tx),
                tx =>
                    setTransactionMessageLifetimeUsingBlockhash(
                        {
                            blockhash: blockhashInfo.blockhash,
                            lastValidBlockHeight: blockhashInfo.lastValidBlockHeight,
                        },
                        tx,
                    ),
            );

            // 6. Fordefi may update the message and broadcasts it itself.
            console.log('Submitting to Fordefi for signing and broadcast...');
            const txSignature = await signAndSendTransactionMessageWithSigners(transaction);
            expect(txSignature).toHaveLength(64);
            console.log(`Fordefi transaction submitted: ${Buffer.from(txSignature).toString('hex')}`);

            // 7. Verify recipient balance increased after Fordefi reports completion
            const { value: recipientBalance } = await rpc.getBalance(recipient).send();
            expect(recipientBalance >= TRANSFER_LAMPORTS).toBe(true);
        },
        TEST_TIMEOUT_MS,
    );

    it.skipIf(!hasBlackBoxEnvVars())(
        'transfers 0.1 SOL on devnet via Fordefi black box signing',
        async () => {
            // 1. Create the Fordefi signer in BLACK BOX mode (no `chain`), using the
            //    black box vault as the origin. Fordefi returns a raw Ed25519 signature
            //    and does not broadcast — the client submits the tx.
            const signer = await createFordefiSigner({
                accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
                maxPollAttempts: 110,
                pollIntervalMs: 1000,
                privateKeyPem: fs.readFileSync(resolvePemPath(process.env.FORDEFI_PRIVATE_KEY_PEM_PATH!), 'utf8'),
                publicKey: process.env.FORDEFI_BB_PUBLIC_KEY!,
                vaultId: process.env.FORDEFI_BB_VAULT_ID!,
            });

            console.log(`Fordefi black box signer address: ${signer.address}`);

            // 2. Set up devnet RPC
            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';
            const wsUrl = process.env.SOLANA_WS_URL ?? 'wss://api.devnet.solana.com';
            const rpc = createSolanaRpc(rpcUrl);
            const rpcSubscriptions = createSolanaRpcSubscriptions(wsUrl);
            const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });

            // 3. Recipient defaults to the native Solana vault's public key.
            const recipient = address(process.env.DEVNET_RECIPIENT ?? process.env.FORDEFI_PUBLIC_KEY!);
            console.log(`Recipient: ${recipient}`);

            // 4. Check signer (black box vault) balance
            const { value: balance } = await rpc.getBalance(signer.address).send();
            console.log(`Signer balance: ${balance} lamports`);
            const needed = TRANSFER_LAMPORTS + 10_000n; // transfer + fee headroom
            expect(balance >= needed).toBe(true);

            // 5. Build the transfer transaction
            const { value: blockhashInfo } = await rpc.getLatestBlockhash().send();
            const instruction = getTransferSolInstruction({
                amount: lamports(TRANSFER_LAMPORTS),
                destination: recipient,
                source: signer,
            });

            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([instruction], tx),
                tx =>
                    setTransactionMessageLifetimeUsingBlockhash(
                        {
                            blockhash: blockhashInfo.blockhash,
                            lastValidBlockHeight: blockhashInfo.lastValidBlockHeight,
                        },
                        tx,
                    ),
            );

            // 6. Sign with Fordefi (black box path)
            console.log('Submitting to Fordefi for black box signing...');
            const signed = await signTransactionMessageWithSigners(transaction);

            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
            console.log('Transaction signed successfully');

            // 7. Broadcast to devnet (black box mode does not auto-broadcast)
            assertIsFullySignedTransaction(signed);
            assertIsTransactionWithBlockhashLifetime(signed);

            console.log('Broadcasting to devnet...');
            await sendAndConfirm(signed, {
                commitment: 'confirmed',
                skipPreflight: true,
            });

            const txSignature = getSignatureFromTransaction(signed);
            console.log(`Transaction confirmed: ${txSignature}`);

            // 8. Verify recipient balance increased
            const { value: recipientBalance } = await rpc.getBalance(recipient).send();
            expect(recipientBalance >= TRANSFER_LAMPORTS).toBe(true);
        },
        TEST_TIMEOUT_MS,
    );

    it.skipIf(!hasRequiredEnvVars())(
        'signs a message on devnet via native Solana message signing',
        async () => {
            // 1. Create the Fordefi signer in native Solana mode
            const signer = await createFordefiSigner({
                accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
                chain: 'solana_devnet',
                maxPollAttempts: 110,
                pollIntervalMs: 1000,
                privateKeyPem: fs.readFileSync(resolvePemPath(process.env.FORDEFI_PRIVATE_KEY_PEM_PATH!), 'utf8'),
                publicKey: process.env.FORDEFI_PUBLIC_KEY!,
                vaultId: process.env.FORDEFI_VAULT_ID!,
            });

            console.log(`Fordefi signer address: ${signer.address}`);

            // 2. Sign a message
            const message = createSignableMessage('Hello from Fordefi!');
            console.log('Submitting message to Fordefi for signing...');

            const [signatureDict] = await signer.signMessages([message]);

            // 3. Verify signature was returned
            expect(signatureDict).toBeDefined();
            const signature = signatureDict![signer.address];
            expect(signature).toBeDefined();
            expect(signature!.length).toBe(64);
            console.log('Message signed successfully');
        },
        TEST_TIMEOUT_MS,
    );
});
