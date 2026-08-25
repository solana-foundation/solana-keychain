import type { SolanaModifyingSigner, SolanaSendingSigner, SolanaSigner } from '@solana/keychain-core';
import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';
import type { CrossmintSendingSigner, CrossmintSignerConfig } from '@solana/keychain-crossmint';
import type {
    FordefiManualSignerConfig,
    FordefiNativeManualSigner,
    FordefiNativeSigner,
    FordefiSignerConfig,
    SolanaChainUniqueId,
} from '@solana/keychain-fordefi';

import type { KeychainSignerConfig } from './types.js';

/**
 * Distributes over unions, unlike a bare `Omit`, which would merge the members
 * into one object type and optional-ize the properties that discriminate them.
 * Fordefi relies on this: its auto and manual configs differ only by `chain` and
 * `pushMode`, which a merged `Omit` would widen until neither branch matched.
 */
type StripBackend<T> = T extends { backend: string } ? Omit<T, 'backend'> : never;

function stripBackend<T extends { backend: string }>({ backend: _, ...rest }: T): StripBackend<T> {
    return rest as StripBackend<T>;
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
    config: FordefiManualSignerConfig & { backend: 'fordefi' },
): Promise<FordefiNativeManualSigner>;
export function createKeychainSigner(
    config: FordefiSignerConfig & { backend: 'fordefi'; chain: SolanaChainUniqueId },
): Promise<FordefiNativeSigner>;
export function createKeychainSigner(
    config:
        | Exclude<KeychainSignerConfig, { backend: 'crossmint' | 'fordefi' }>
        | (FordefiSignerConfig & { backend: 'fordefi'; chain?: undefined }),
): Promise<SolanaSigner>;
export function createKeychainSigner(
    config: KeychainSignerConfig,
): Promise<SolanaModifyingSigner | SolanaSendingSigner | SolanaSigner>;
export async function createKeychainSigner(
    config: KeychainSignerConfig,
): Promise<SolanaModifyingSigner | SolanaSendingSigner | SolanaSigner> {
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
