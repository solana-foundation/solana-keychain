import { createAwsKmsSigner } from '@solana/keychain-aws-kms';
import { createCdpSigner } from '@solana/keychain-cdp';
import type { SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';
import { createCrossmintSigner } from '@solana/keychain-crossmint';
import { createDfnsSigner } from '@solana/keychain-dfns';
import { createFireblocksSigner } from '@solana/keychain-fireblocks';
import { createGcpKmsSigner } from '@solana/keychain-gcp-kms';
import { createParaSigner } from '@solana/keychain-para';
import { createPrivySigner } from '@solana/keychain-privy';
import { createTurnkeySigner } from '@solana/keychain-turnkey';
import { createVaultSigner } from '@solana/keychain-vault';

import type { KeychainSignerConfig } from './types.js';

function stripBackend<T extends { backend: string }>({ backend: _, ...rest }: T): Omit<T, 'backend'> {
    return rest;
}

/**
 * Create a {@link SolanaSigner} from a backend-tagged configuration.
 *
 * Dispatches to the correct `createXxxSigner()` factory based on
 * the `backend` discriminant.
 *
 * @example
 * ```typescript
 * const signer = await createKeychainSigner({
 *     backend: 'privy',
 *     appId: '...',
 *     appSecret: '...',
 *     walletId: '...',
 * });
 * ```
 */
export async function createKeychainSigner(config: KeychainSignerConfig): Promise<SolanaSigner> {
    switch (config.backend) {
        case 'aws-kms':
            return createAwsKmsSigner(stripBackend(config));
        case 'cdp':
            return await createCdpSigner(stripBackend(config));
        case 'crossmint':
            return await createCrossmintSigner(stripBackend(config));
        case 'dfns':
            return await createDfnsSigner(stripBackend(config));
        case 'fireblocks':
            return await createFireblocksSigner(stripBackend(config));
        case 'gcp-kms':
            return createGcpKmsSigner(stripBackend(config));
        case 'para':
            return await createParaSigner(stripBackend(config));
        case 'privy':
            return await createPrivySigner(stripBackend(config));
        case 'turnkey':
            return createTurnkeySigner(stripBackend(config));
        case 'vault':
            return createVaultSigner(stripBackend(config));
        default: {
            const _exhaustive: never = config;
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unknown backend: ${String((_exhaustive as { backend: string }).backend)}`,
            });
        }
    }
}
