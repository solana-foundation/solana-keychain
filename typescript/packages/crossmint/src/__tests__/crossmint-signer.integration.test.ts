import {
    appendTransactionMessageInstructions,
    createSignableMessage,
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

import { createCrossmintSigner } from '../crossmint-signer.js';

config();

const REQUIRED_ENV_VARS = ['CROSSMINT_API_KEY', 'CROSSMINT_WALLET_LOCATOR'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

describe('CrossmintSigner Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'signs transactions with managed flow',
        async () => {
            const signer = await createCrossmintSigner({
                apiKey: process.env.CROSSMINT_API_KEY!,
                walletLocator: process.env.CROSSMINT_WALLET_LOCATOR!,
                apiBaseUrl: process.env.CROSSMINT_API_BASE_URL,
                maxPollAttempts: process.env.CROSSMINT_MAX_POLL_ATTEMPTS
                    ? Number(process.env.CROSSMINT_MAX_POLL_ATTEMPTS)
                    : undefined,
                pollIntervalMs: process.env.CROSSMINT_POLL_INTERVAL_MS
                    ? Number(process.env.CROSSMINT_POLL_INTERVAL_MS)
                    : undefined,
                signer: process.env.CROSSMINT_SIGNER,
            });

            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';
            const rpc = createSolanaRpc(rpcUrl);
            const {
                value: { blockhash, lastValidBlockHeight },
            } = await rpc.getLatestBlockhash().send();

            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([getAddMemoInstruction({ memo: 'Crossmint test' })], tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            const signed = await signTransactionMessageWithSigners(transaction);
            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
        },
        120_000,
    );

    it.skipIf(!hasRequiredEnvVars())('returns not supported for signMessages', async () => {
        const signer = await createCrossmintSigner({
            apiKey: process.env.CROSSMINT_API_KEY!,
            walletLocator: process.env.CROSSMINT_WALLET_LOCATOR!,
            apiBaseUrl: process.env.CROSSMINT_API_BASE_URL,
            signer: process.env.CROSSMINT_SIGNER,
        });

        const message = createSignableMessage(new Uint8Array([1, 2, 3]));
        await expect(signer.signMessages([message])).rejects.toThrow('not supported');
    });

    it.skipIf(!hasRequiredEnvVars())('checks availability', async () => {
        const signer = await createCrossmintSigner({
            apiKey: process.env.CROSSMINT_API_KEY!,
            walletLocator: process.env.CROSSMINT_WALLET_LOCATOR!,
            apiBaseUrl: process.env.CROSSMINT_API_BASE_URL,
            signer: process.env.CROSSMINT_SIGNER,
        });
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
