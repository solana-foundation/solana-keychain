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

import { CdpSigner } from '../cdp-signer.js';

config();

const REQUIRED_ENV_VARS = ['CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET', 'CDP_SOLANA_ADDRESS'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

async function createCdpSigner(): Promise<CdpSigner> {
    return CdpSigner.create({
        cdpApiKeyId: process.env.CDP_API_KEY_ID!,
        cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
        cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
        address: process.env.CDP_SOLANA_ADDRESS!,
    });
}

describe('CdpSigner Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'signs transactions with CDP',
        async () => {
            const signer = await createCdpSigner();
            const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';

            // Get real blockhash from devnet
            const rpc = createSolanaRpc(rpcUrl);
            const {
                value: { blockhash, lastValidBlockHeight },
            } = await rpc.getLatestBlockhash().send();

            // Create a memo transaction (doesn't require funds on the signer)
            const transaction = pipe(
                createTransactionMessage({ version: 0 }),
                tx => setTransactionMessageFeePayerSigner(signer, tx),
                tx => appendTransactionMessageInstructions([getAddMemoInstruction({ memo: 'CDP keychain test' })], tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            // Sign via CDP
            const signed = await signTransactionMessageWithSigners(transaction);

            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
        },
        60_000,
    );

    it.skipIf(!hasRequiredEnvVars())(
        'signs messages with CDP',
        async () => {
            const signer = await createCdpSigner();

            const message = {
                content: new TextEncoder().encode('CDP keychain test'),
                signatures: {},
            };

            const result = await signer.signMessages([message]);

            expect(result).toHaveLength(1);
            expect(result[0]?.[signer.address]).toBeDefined();
            expect(result[0]?.[signer.address]?.length).toBe(64);
        },
        30_000,
    );

    it.skipIf(!hasRequiredEnvVars())(
        'checks availability',
        async () => {
            const signer = await createCdpSigner();
            const available = await signer.isAvailable();
            expect(available).toBe(true);
        },
        30_000,
    );
});
