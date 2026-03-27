import { type Address, assertIsAddress } from '@solana/addresses';

import { createSigner } from './create-signer.js';
import type { KeychainSignerConfig } from './types.js';

/**
 * Resolve the Solana address for a signer configuration without
 * setting up the full signing pipeline.
 *
 * For backends that include the public key in their config (AWS KMS,
 * CDP, GCP KMS, Turnkey, Vault), this returns the address directly
 * with no network call. For backends that must fetch the public key
 * from a remote API (Crossmint, Dfns, Fireblocks, Para, Privy),
 * this initialises the signer and reads its address.
 *
 * @example
 * ```typescript
 * const address = await resolveAddress({
 *     backend: 'vault',
 *     vaultAddr: 'https://vault.example.com',
 *     vaultToken: 'hvs.xxx',
 *     keyName: 'my-key',
 *     publicKey: '4Nd1m...',
 * });
 * // Returns '4Nd1m...' immediately — no network call
 * ```
 */
export async function resolveAddress(config: KeychainSignerConfig): Promise<Address> {
    switch (config.backend) {
        // Backends with publicKey in config — no network call needed
        case 'aws-kms':
        case 'gcp-kms':
        case 'turnkey':
        case 'vault':
            assertIsAddress(config.publicKey);
            return config.publicKey;

        // CDP provides address directly in config
        case 'cdp':
            assertIsAddress(config.address);
            return config.address;

        // Backends that fetch the address from a remote API
        case 'crossmint':
        case 'dfns':
        case 'fireblocks':
        case 'para':
        case 'privy': {
            const signer = await createSigner(config);
            return signer.address;
        }

        default:
            throw new Error(`Unknown backend: ${String((config as { backend: string }).backend)}`);
    }
}
