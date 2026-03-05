/**
 * Fireblocks PROGRAM_CALL integration tests (devnet, not LiteSVM)
 *
 * Unlike other signers, Fireblocks PROGRAM_CALL mode signs AND broadcasts
 * the transaction to Solana through Fireblocks' infrastructure. The signed
 * transaction never returns to the caller — only a txHash comes back after
 * polling. This means LiteSVM (used by runSignerIntegrationTest) can never
 * observe the transaction, so we test against devnet directly.
 *
 * RAW mode returns a raw signature but is not available on the Fireblocks
 * sandbox/testnet environment used in CI.
 */
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

import { createFireblocksSigner } from '../fireblocks-signer.js';

config();

const REQUIRED_ENV_VARS = ['FIREBLOCKS_API_KEY', 'FIREBLOCKS_PRIVATE_KEY_PEM', 'FIREBLOCKS_VAULT_ACCOUNT_ID'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

describe('FireblocksSigner Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'signs transactions with PROGRAM_CALL',
        async () => {
            const signer = await createFireblocksSigner({
                apiKey: process.env.FIREBLOCKS_API_KEY!,
                assetId: process.env.FIREBLOCKS_ASSET_ID ?? 'SOL_TEST',
                privateKeyPem: process.env.FIREBLOCKS_PRIVATE_KEY_PEM!,
                useProgramCall: true,
                vaultAccountId: process.env.FIREBLOCKS_VAULT_ACCOUNT_ID!,
            });
            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';

            const rpc = createSolanaRpc(rpcUrl);
            const {
                value: { blockhash, lastValidBlockHeight },
            } = await rpc.getLatestBlockhash().send();

            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([getAddMemoInstruction({ memo: 'Fireblocks test' })], tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            const signed = await signTransactionMessageWithSigners(transaction);

            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
        },
        120_000,
    );

    // RAW signing not available on Fireblocks testnet/sandbox
    it.skip('signs messages with real API', () => {});

    it.skipIf(!hasRequiredEnvVars())('checks availability', async () => {
        const signer = await createFireblocksSigner({
            apiKey: process.env.FIREBLOCKS_API_KEY!,
            assetId: process.env.FIREBLOCKS_ASSET_ID ?? 'SOL_TEST',
            privateKeyPem: process.env.FIREBLOCKS_PRIVATE_KEY_PEM!,
            vaultAccountId: process.env.FIREBLOCKS_VAULT_ACCOUNT_ID!,
        });
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
