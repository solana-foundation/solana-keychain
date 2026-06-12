import type { KeychainSignerConfig } from '@solana/keychain';
import { createKeychainSigner } from '@solana/keychain';
import { extendClient } from '@solana/kit';

/**
 * Creates a keychain signer from a backend-tagged configuration and sets it
 * as both the `payer` and `identity` properties on the client.
 *
 * This is a convenience shorthand for installing {@link keychainPayer} and
 * {@link keychainIdentity} with the same configuration, without creating the
 * signer twice.
 *
 * A new signer is created each time the plugin is applied to a client. To
 * share one signer across clients, create it with `createKeychainSigner()`
 * and install it with `@solana/kit-plugin-signer`'s `signer()` instead.
 *
 * @param config - The backend-tagged keychain signer configuration.
 *
 * @example
 * ```ts
 * import { createClient } from '@solana/kit';
 * import { keychainSigner } from '@solana/keychain-kit-plugin';
 *
 * const client = await createClient().use(
 *     keychainSigner({ backend: 'privy', appId, appSecret, walletId }),
 * );
 * ```
 *
 * @see {@link keychainPayer}
 * @see {@link keychainIdentity}
 */
export function keychainSigner(config: KeychainSignerConfig) {
    return async <TClient extends object>(client: TClient) => {
        const signer = await createKeychainSigner(config);
        return extendClient(client, { identity: signer, payer: signer });
    };
}

/**
 * Creates a keychain signer from a backend-tagged configuration and sets it
 * as the `payer` property on the client.
 *
 * The payer is the signer responsible for paying transaction fees and
 * storage costs (i.e. rent for newly created accounts).
 *
 * @param config - The backend-tagged keychain signer configuration.
 *
 * @example
 * ```ts
 * import { createClient } from '@solana/kit';
 * import { keychainPayer } from '@solana/keychain-kit-plugin';
 *
 * const client = await createClient().use(
 *     keychainPayer({ backend: 'vault', vaultUrl, vaultToken, keyName }),
 * );
 * ```
 *
 * @see {@link keychainIdentity}
 * @see {@link keychainSigner}
 */
export function keychainPayer(config: KeychainSignerConfig) {
    return async <TClient extends object>(client: TClient) => {
        const payer = await createKeychainSigner(config);
        return extendClient(client, { payer });
    };
}

/**
 * Creates a keychain signer from a backend-tagged configuration and sets it
 * as the `identity` property on the client.
 *
 * The identity is the signer representing the wallet that owns things in
 * the application, such as the authority over accounts, tokens, or other
 * on-chain assets.
 *
 * @param config - The backend-tagged keychain signer configuration.
 *
 * @example
 * ```ts
 * import { createClient } from '@solana/kit';
 * import { keychainIdentity } from '@solana/keychain-kit-plugin';
 *
 * const client = await createClient().use(
 *     keychainIdentity({ backend: 'turnkey', ...turnkeyConfig }),
 * );
 * ```
 *
 * @see {@link keychainPayer}
 * @see {@link keychainSigner}
 */
export function keychainIdentity(config: KeychainSignerConfig) {
    return async <TClient extends object>(client: TClient) => {
        const identity = await createKeychainSigner(config);
        return extendClient(client, { identity });
    };
}
