import {
    appendTransactionMessageInstructions,
    createSolanaRpc,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { getAddMemoInstruction } from '@solana-program/memo';
import { config } from 'dotenv';
import { describe, expect, it } from 'vitest';

import { FireblocksSigner } from '../fireblocks-signer.js';

config();

const REQUIRED_ENV_VARS = ['FIREBLOCKS_API_KEY', 'FIREBLOCKS_PRIVATE_KEY_PEM', 'FIREBLOCKS_VAULT_ACCOUNT_ID'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

async function createFireblocksSigner(): Promise<FireblocksSigner> {
    const signer = new FireblocksSigner({
        apiKey: process.env.FIREBLOCKS_API_KEY!,
        assetId: process.env.FIREBLOCKS_ASSET_ID ?? 'SOL_TEST',
        privateKeyPem: process.env.FIREBLOCKS_PRIVATE_KEY_PEM!,
        useProgramCall: true,
        vaultAccountId: process.env.FIREBLOCKS_VAULT_ACCOUNT_ID!,
    });
    await signer.init();
    return signer;
}

describe('FireblocksSigner Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'signs transactions with PROGRAM_CALL',
        async () => {
            const signer = await createFireblocksSigner();
            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';

            // Get real blockhash from devnet
            const rpc = createSolanaRpc(rpcUrl);
            const {
                value: { blockhash, lastValidBlockHeight },
            } = await rpc.getLatestBlockhash().send();

            // Create memo transaction (doesn't need funds)
            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([getAddMemoInstruction({ memo: 'Fireblocks test' })], tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            // Sign via Fireblocks (PROGRAM_CALL broadcasts to Solana)
            const signed = await signTransactionMessageWithSigners(transaction);

            // Verify signature returned
            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
        },
        120_000,
    ); // 2 minute timeout for PROGRAM_CALL

    // RAW signing not available on Fireblocks testnet/sandbox
    it.skip('signs messages with real API', () => {});

    it.skipIf(!hasRequiredEnvVars())('checks availability', async () => {
        const signer = await createFireblocksSigner();
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
