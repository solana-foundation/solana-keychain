import { type Address, assertIsAddress } from '@solana/addresses';
import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';

import { createKeychainSigner } from './create-keychain-signer.js';
import type { KeychainSignerConfig } from './types.js';

/**
 * Resolve the Solana address for a signer configuration without
 * setting up the full signing pipeline.
 *
 * For backends that include the public key in their config (AWS KMS,
 * CDP, GCP KMS, Turnkey, Vault), this returns the address directly
 * with no network call. For backends that must fetch the public key
 * from a remote API (Crossmint, Dfns, Fireblocks, Openfort, Para, Privy, Utila),
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

        // Backends that derive or fetch the address from key/api material
        case 'crossmint':
        case 'dfns':
        case 'fireblocks':
        case 'memory':
        case 'openfort':
        case 'para':
        case 'privy':
        case 'utila': {
            const signer = await createKeychainSigner(config);
            return signer.address;
        }

        default: {
            const _exhaustive: never = config;
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unknown backend: ${String((_exhaustive as { backend: string }).backend)}`,
            });
        }
    }
}
