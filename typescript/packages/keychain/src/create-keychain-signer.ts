import type { SolanaSendingSigner, SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';
import type { CrossmintSendingSigner, CrossmintSignerConfig } from '@solana/keychain-crossmint';
import type { FordefiNativeSigner, FordefiSignerConfig, SolanaChainUniqueId } from '@solana/keychain-fordefi';

import type { KeychainSignerConfig } from './types.js';

function stripBackend<T extends { backend: string }>({ backend: _, ...rest }: T): Omit<T, 'backend'> {
    return rest;
}

/**
 * Create a {@link SolanaSigner} from a backend-tagged configuration.
 *
 * Dispatches to the correct `createXxxSigner()` factory based on
 * the `backend` discriminant. Each backend package is loaded with a
 * dynamic `import()` so bundlers only include the backend(s) a
 * program actually dispatches to, not every vendor SDK.
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
export function createKeychainSigner(
    config: CrossmintSignerConfig & { backend: 'crossmint' },
): Promise<CrossmintSendingSigner>;
export function createKeychainSigner(
    config: FordefiSignerConfig & { backend: 'fordefi'; chain: SolanaChainUniqueId },
): Promise<FordefiNativeSigner>;
export function createKeychainSigner(config: KeychainSignerConfig): Promise<SolanaSigner>;
export async function createKeychainSigner(config: KeychainSignerConfig): Promise<SolanaSendingSigner | SolanaSigner> {
    switch (config.backend) {
        case 'aws-kms': {
            const { createAwsKmsSigner } = await import('@solana/keychain-aws-kms');
            return createAwsKmsSigner(stripBackend(config));
        }
        case 'cdp': {
            const { createCdpSigner } = await import('@solana/keychain-cdp');
            return await createCdpSigner(stripBackend(config));
        }
        case 'crossmint': {
            const { createCrossmintSigner } = await import('@solana/keychain-crossmint');
            return await createCrossmintSigner(stripBackend(config));
        }
        case 'dfns': {
            const { createDfnsSigner } = await import('@solana/keychain-dfns');
            return await createDfnsSigner(stripBackend(config));
        }
        case 'fireblocks': {
            const { createFireblocksSigner } = await import('@solana/keychain-fireblocks');
            return await createFireblocksSigner(stripBackend(config));
        }
        case 'fordefi': {
            const { createFordefiSigner } = await import('@solana/keychain-fordefi');
            return await createFordefiSigner(stripBackend(config));
        }
        case 'gcp-kms': {
            const { createGcpKmsSigner } = await import('@solana/keychain-gcp-kms');
            return createGcpKmsSigner(stripBackend(config));
        }
        case 'memory': {
            const { createMemorySigner } = await import('@solana/keychain-memory');
            return await createMemorySigner(stripBackend(config));
        }
        case 'openfort': {
            const { createOpenfortSigner } = await import('@solana/keychain-openfort');
            return await createOpenfortSigner(stripBackend(config));
        }
        case 'para': {
            const { createParaSigner } = await import('@solana/keychain-para');
            return await createParaSigner(stripBackend(config));
        }
        case 'privy': {
            const { createPrivySigner } = await import('@solana/keychain-privy');
            return await createPrivySigner(stripBackend(config));
        }
        case 'turnkey': {
            const { createTurnkeySigner } = await import('@solana/keychain-turnkey');
            return createTurnkeySigner(stripBackend(config));
        }
        case 'utila': {
            const { createUtilaSigner } = await import('@solana/keychain-utila');
            return await createUtilaSigner(stripBackend(config));
        }
        case 'vault': {
            const { createVaultSigner } = await import('@solana/keychain-vault');
            return createVaultSigner(stripBackend(config));
        }
        default: {
            const _exhaustive: never = config;
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unknown backend: ${String((_exhaustive as { backend: string }).backend)}`,
            });
        }
    }
}
