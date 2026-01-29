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

import { AwsKmsSigner } from '../aws-kms-signer.js';

config();

const REQUIRED_ENV_VARS = ['AWS_KMS_KEY_ID', 'AWS_KMS_SIGNER_PUBKEY'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

function createAwsKmsSigner(): AwsKmsSigner {
    return new AwsKmsSigner({
        keyId: process.env.AWS_KMS_KEY_ID!,
        publicKey: process.env.AWS_KMS_SIGNER_PUBKEY!,
        region: process.env.AWS_KMS_REGION,
    });
}

describe('AwsKmsSigner Integration', () => {
    it.skipIf(!hasRequiredEnvVars())(
        'signs transactions with AWS KMS',
        async () => {
            const signer = createAwsKmsSigner();
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
                tx => appendTransactionMessageInstructions([getAddMemoInstruction({ memo: 'AWS KMS test' })], tx),
                tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
            );

            // Sign via AWS KMS
            const signed = await signTransactionMessageWithSigners(transaction);

            // Verify signature returned
            expect(signed.signatures[signer.address]).toBeDefined();
            expect(signed.signatures[signer.address]?.length).toBe(64);
        },
        60_000,
    ); // 1 minute timeout

    it.skipIf(!hasRequiredEnvVars())('signs messages', async () => {
        const signer = createAwsKmsSigner();

        const message = {
            content: new Uint8Array([1, 2, 3, 4, 5]),
            signatures: {},
        };

        const result = await signer.signMessages([message]);

        expect(result).toHaveLength(1);
        expect(result[0]?.[signer.address]).toBeDefined();
        expect(result[0]?.[signer.address]?.length).toBe(64);
    });

    it.skipIf(!hasRequiredEnvVars())('checks availability', async () => {
        const signer = createAwsKmsSigner();
        const available = await signer.isAvailable();
        expect(available).toBe(true);
    });
});
