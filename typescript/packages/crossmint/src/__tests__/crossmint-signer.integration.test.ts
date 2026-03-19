import {
    type Blockhash,
    createSignableMessage,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
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

describe('CrossmintSigner Integration', () => {
    it.skipIf(!process.env.CROSSMINT_API_KEY)('signs transactions with real API', async () => {
        const { createSigner } = await getConfig(['signTransaction']);
        const signer = await createSigner();

        const { blockhash, lastValidBlockHeight } = await getLatestBlockhash();
        const transaction = pipe(
            createTransactionMessage({ version: 0 }),
            tx => setTransactionMessageFeePayerSigner(signer, tx),
            tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
        );

        const signedTx = await signTransactionMessageWithSigners(transaction);

        expect(signedTx.signatures[signer.address]).toBeDefined();
        expect(signedTx.signatures[signer.address]?.byteLength).toBe(64);
    });

    it.skipIf(!process.env.CROSSMINT_API_KEY)('returns not supported for signMessages', async () => {
        const { createSigner } = await getConfig(['signMessage']);
        const signer = await createSigner();
        const message = createSignableMessage(new Uint8Array([1, 2, 3]));
        await expect(signer.signMessages([message])).rejects.toThrow('not supported');
    });

    it.skipIf(!process.env.CROSSMINT_API_KEY)('checks availability', async () => {
        const { createSigner } = await getConfig([]);
        const signer = await createSigner();
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
