/**
 * Fireblocks integration tests.
 *
 * Neither signing mode is exercised against the live API here: RAW signing is
 * not available on the Fireblocks sandbox/testnet environment used in CI, and
 * PROGRAM_CALL must be enabled for the workspace by Fireblocks.
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
    // RAW signing not available on Fireblocks testnet/sandbox
    it.skip('signs messages with real API', () => {});

    // PROGRAM_CALL must be enabled for the workspace by Fireblocks
    it.skip('signs transactions with real API in PROGRAM_CALL sign-only mode', () => {});

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
