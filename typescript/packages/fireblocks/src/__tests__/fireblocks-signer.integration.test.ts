/**
 * Fireblocks integration tests.
 *
 * The signer only supports Fireblocks RAW signing. Fireblocks PROGRAM_CALL
 * signing is unsupported: it broadcasts the transaction on-chain and only
 * returns a broadcast transaction id, not a reusable signer-bound signature.
 * `useProgramCall: true` is therefore rejected at construction, before any
 * network call or broadcast can occur (fail closed).
 *
 * RAW mode returns a raw signature but is not available on the Fireblocks
 * sandbox/testnet environment used in CI, so it is not exercised here.
 */
import { config } from 'dotenv';
import { describe, expect, it } from 'vitest';

import { createFireblocksSigner } from '../fireblocks-signer.js';

config();

const REQUIRED_ENV_VARS = ['FIREBLOCKS_API_KEY', 'FIREBLOCKS_PRIVATE_KEY_PEM', 'FIREBLOCKS_VAULT_ACCOUNT_ID'];

function hasRequiredEnvVars(): boolean {
    return REQUIRED_ENV_VARS.every(v => process.env[v]);
}

describe('FireblocksSigner Integration', () => {
    it('fails closed for PROGRAM_CALL by rejecting at construction before any broadcast', async () => {
        await expect(
            createFireblocksSigner({
                apiKey: 'test-api-key',
                assetId: 'SOL_TEST',
                privateKeyPem: 'test-private-key-pem',
                useProgramCall: true,
                vaultAccountId: '0',
            }),
        ).rejects.toMatchObject({
            code: 'SIGNER_CONFIG_ERROR',
            message: expect.stringContaining('useProgramCall'),
        });
    });

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
