import { getTransferSolInstruction } from '@solana-program/system';
import { assertSignatureValid } from '@solana/keychain-core';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import {
    address,
    appendTransactionMessageInstructions,
    type Base64EncodedWireTransaction,
    type Blockhash,
    compileTransaction,
    createTransactionMessage,
    getBase58Decoder,
    getBase64EncodedWireTransaction,
    lamports,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signAndSendTransactionMessageWithSigners,
    type TransactionSigner,
} from '@solana/kit';
import { config } from 'dotenv';
import { describe, expect, it } from 'vitest';
import { createFordefiSigner } from '../fordefi-signer';
import type { SolanaChainUniqueId } from '../types';
import { getConfig } from './setup';
config();

// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so we extend the per-test timeout well beyond the
// vitest default of 30s.
const TEST_TIMEOUT_MS = 120_000;

const RPC_URL = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';
const TRANSFER_LAMPORTS = lamports(1n);
const CONFIRMATION_TIMEOUT_MS = 60_000;
const CONFIRMATION_POLL_INTERVAL_MS = 2_000;

async function callRpc<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(RPC_URL, {
        body: JSON.stringify({ id: 1, jsonrpc: '2.0', method, params }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
    const json = (await response.json()) as { error?: unknown; result: T };
    if (json.error) {
        throw new Error(`${method} RPC error: ${JSON.stringify(json.error)}`);
    }
    return json.result;
}

async function getLatestBlockhash(): Promise<{ blockhash: Blockhash; lastValidBlockHeight: bigint }> {
    const { value } = await callRpc<{ value: { blockhash: Blockhash; lastValidBlockHeight: number } }>(
        'getLatestBlockhash',
        [{ commitment: 'finalized' }],
    );
    return { blockhash: value.blockhash, lastValidBlockHeight: BigInt(value.lastValidBlockHeight) };
}

async function sendWireTransaction(wireTransaction: Base64EncodedWireTransaction): Promise<string> {
    // Fordefi stamps the recent blockhash seconds before it signs, so a
    // finalized-commitment preflight reports BlockhashNotFound and rejects the send.
    return await callRpc<string>('sendTransaction', [
        wireTransaction,
        { encoding: 'base64', preflightCommitment: 'processed' },
    ]);
}

async function confirmSignature(signature: string, rebroadcast?: Base64EncodedWireTransaction): Promise<void> {
    const deadline = Date.now() + CONFIRMATION_TIMEOUT_MS;

    while (Date.now() < deadline) {
        const { value } = await callRpc<{ value: ({ confirmationStatus: string | null; err: unknown } | null)[] }>(
            'getSignatureStatuses',
            [[signature], { searchTransactionHistory: true }],
        );
        const status = value[0];

        if (status) {
            if (status.err) {
                throw new Error(`Transaction failed on-chain: ${JSON.stringify(status.err)}`);
            }
            if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
                return;
            }
        }

        if (rebroadcast) {
            // A sent transaction can be dropped and never land, so resend it
            // between polls while its blockhash is still valid.
            await sendWireTransaction(rebroadcast).catch(() => undefined);
        }
        await new Promise(resolve => setTimeout(resolve, CONFIRMATION_POLL_INTERVAL_MS));
    }

    throw new Error(`Timed out waiting for confirmation of ${signature}`);
}

function nativeConfig() {
    return {
        accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
        apiBaseUrl: process.env.FORDEFI_API_BASE_URL,
        chain: (process.env.FORDEFI_CHAIN ?? 'solana_devnet') as SolanaChainUniqueId,
        maxPollAttempts: 110,
        pollIntervalMs: 1000,
        privateKeyPem: process.env.FORDEFI_PRIVATE_KEY_PEM!,
        publicKey: process.env.FORDEFI_PUBLIC_KEY!,
        vaultId: process.env.FORDEFI_VAULT_ID!,
    };
}

async function buildUnsignedDevnetTransfer<TSigner extends TransactionSigner<string>>(feePayer: TSigner) {
    const { blockhash, lastValidBlockHeight } = await getLatestBlockhash();
    const destination = address(process.env.DEVNET_RECIPIENT ?? feePayer.address);

    return pipe(
        createTransactionMessage({ version: 0 }),
        tx => setTransactionMessageFeePayerSigner(feePayer, tx),
        tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
        tx =>
            appendTransactionMessageInstructions(
                [getTransferSolInstruction({ amount: TRANSFER_LAMPORTS, destination, source: feePayer })],
                tx,
            ),
    );
}

describe('FordefiSigner Integration', () => {
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signTransaction']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs messages with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signMessage']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'simulates transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
        },
        TEST_TIMEOUT_MS,
    );

    it.skipIf(!process.env.FORDEFI_VAULT_ID)(
        'native auto mode signs and broadcasts a devnet transfer',
        async () => {
            const signer = await createFordefiSigner({ ...nativeConfig(), pushMode: 'auto' as const });
            const transactionMessage = await buildUnsignedDevnetTransfer(signer);

            const signatureBytes = await signAndSendTransactionMessageWithSigners(transactionMessage);

            expect(signatureBytes.byteLength).toBe(64);

            await confirmSignature(getBase58Decoder().decode(signatureBytes));
        },
        TEST_TIMEOUT_MS,
    );

    it.skipIf(!process.env.FORDEFI_VAULT_ID)(
        'native manual mode signs a devnet transfer the caller broadcasts',
        async () => {
            const signer = await createFordefiSigner({ ...nativeConfig(), pushMode: 'manual' as const });
            const transactionMessage = await buildUnsignedDevnetTransfer(signer);

            const signedTransactions = await signer.modifyAndSignTransactions([compileTransaction(transactionMessage)]);
            expect(signedTransactions).toHaveLength(1);
            const signedTransaction = signedTransactions[0]!;

            const vaultSignature = signedTransaction.signatures[signer.address];
            expect(vaultSignature?.byteLength).toBe(64);
            await assertSignatureValid({
                data: signedTransaction.messageBytes,
                signature: vaultSignature!,
                signerAddress: signer.address,
            });

            const wireTransaction = getBase64EncodedWireTransaction(signedTransaction);
            const transactionSignature = await sendWireTransaction(wireTransaction);

            await confirmSignature(transactionSignature, wireTransaction);
        },
        TEST_TIMEOUT_MS,
    );
});
