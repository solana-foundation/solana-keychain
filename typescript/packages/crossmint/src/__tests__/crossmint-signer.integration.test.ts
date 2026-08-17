import {
    type Blockhash,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signAndSendTransactionMessageWithSigners,
} from '@solana/kit';
import { describe, expect, it } from 'vitest';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

const RPC_URL = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';

async function getLatestBlockhash() {
    const res = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getLatestBlockhash',
            params: [{ commitment: 'finalized' }],
        }),
    });
    const json = (await res.json()) as { result: { value: { blockhash: Blockhash; lastValidBlockHeight: bigint } } };
    return json.result.value;
}

// Crossmint is broadcast-managed: "success" requires the transaction to land
// on devnet, so signing can take the signer's full polling budget (60 × 1s in
// crossmint-signer.ts). The test timeout must exceed that budget so the
// signer's own timeout error surfaces instead of a vitest kill.
const SIGN_TEST_TIMEOUT_MS = 90_000;

describe('CrossmintSigner Integration', () => {
    it.skipIf(!process.env.CROSSMINT_API_KEY)(
        'signs and broadcasts transactions with real API',
        { timeout: SIGN_TEST_TIMEOUT_MS },
        async () => {
            const { createSigner } = await getConfig(['signTransaction']);
            const signer = await createSigner();

            const { blockhash, lastValidBlockHeight } = await getLatestBlockhash();
            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            // Crossmint broadcasts server-side, so the result is the signature of
            // the transaction it landed, not a signature over these message bytes.
            const signature = await signAndSendTransactionMessageWithSigners(transaction);

            expect(signature).toBeDefined();
            expect(signature.byteLength).toBe(64);
        },
    );

    it.skipIf(!process.env.CROSSMINT_API_KEY)('does not expose partial-signer methods', async () => {
        const { createSigner } = await getConfig([]);
        const signer = await createSigner();
        expect('signMessages' in signer).toBe(false);
        expect('signTransactions' in signer).toBe(false);
    });

    it.skipIf(!process.env.CROSSMINT_API_KEY)('checks availability', async () => {
        const { createSigner } = await getConfig([]);
        const signer = await createSigner();
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
