import type {
    FordefiManualSignerConfig,
    FordefiSignerConfig,
    KeychainSignerConfig,
    SolanaModifyingSigner,
    SolanaSigner,
} from '@solana/keychain';
import {
    assertIsSolanaSigner,
    createKeychainSigner,
    isSolanaModifyingSigner,
    SignerErrorCode,
    throwSignerError,
} from '@solana/keychain';
import { extendClient } from '@solana/kit';

/**
 * Backend configurations these plugins accept: every keychain backend except
 * the managed-broadcast ones — Crossmint, and Fordefi in native auto mode
 * (`chain` set, `pushMode` left at `auto`). Those backends broadcast
 * server-side, so they expose `signAndSendTransactions` and no
 * `signTransactions`, and cannot serve as a client `payer` or `identity`:
 * client send flows build, sign, and broadcast themselves, and Kit routes a
 * sending signer only through `signAndSendTransactionMessageWithSigners()`.
 * Create those signers with `createKeychainSigner()` and use that function
 * directly instead.
 *
 * Fordefi native *manual* mode is accepted. It rewrites the transaction but
 * does not broadcast, making it a `TransactionModifyingSigner`, which Kit runs
 * ahead of the partial signers in its normal signing pipeline.
 */
export type KeychainKitPluginConfig =
    | Exclude<KeychainSignerConfig, { backend: 'crossmint' | 'fordefi' }>
    | (FordefiManualSignerConfig & { backend: 'fordefi' })
    | (FordefiSignerConfig & { backend: 'fordefi'; chain?: undefined });

/**
 * The client-facing signer shape a plugin config produces. Only Fordefi native
 * manual mode yields a modifying signer; every other accepted backend is a
 * partial signer, and its statically known `signTransactions`/`signMessages`
 * must survive on `client.payer`/`client.identity`.
 */
type ClientSigner<TConfig extends KeychainKitPluginConfig> = TConfig extends FordefiManualSignerConfig & {
    backend: 'fordefi';
}
    ? SolanaModifyingSigner
    : SolanaSigner;

/**
 * The managed-broadcast exclusion above only protects TypeScript callers, so
 * the config is also rejected at runtime — before `createKeychainSigner`
 * runs, since the excluded backends authenticate against their provider
 * during construction. The signer-shape assertion afterwards is the backstop
 * for any future backend whose factory returns a sending signer.
 */
async function createClientSigner<TConfig extends KeychainKitPluginConfig>(
    config: TConfig,
): Promise<ClientSigner<TConfig>> {
    const { backend } = config as KeychainSignerConfig;
    const broadcastsServerSide =
        backend === 'crossmint' ||
        (backend === 'fordefi' &&
            (config as { chain?: unknown }).chain !== undefined &&
            (config as { pushMode?: unknown }).pushMode !== 'manual');
    if (broadcastsServerSide) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `The '${backend}' backend broadcasts transactions server-side and cannot serve as a Kit client payer/identity. Create it with createKeychainSigner() and use signAndSendTransaction() instead.`,
        });
    }
    const signer = await createKeychainSigner(config);
    // A modifying signer is a valid payer/identity; anything else must be a
    // partial signer, which also catches a sending signer slipping through.
    if (!isSolanaModifyingSigner(signer)) {
        assertIsSolanaSigner(signer);
    }
    return signer as ClientSigner<TConfig>;
}

/**
 * Fordefi native manual signing requires the vault to be the transaction fee
 * payer, so an identity-only installation would fail on its first real sign.
 * {@link keychainIdentity} rejects that config here; its parameter type
 * excludes it as well.
 */
function assertServesAsIdentityAlone(config: KeychainKitPluginConfig): void {
    const { backend } = config as KeychainSignerConfig;
    if (backend === 'fordefi' && (config as { pushMode?: unknown }).pushMode === 'manual') {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message:
                'Fordefi native manual mode must be the transaction fee payer and cannot serve as an identity-only signer. Install it with keychainSigner() or keychainPayer() instead.',
        });
    }
}

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
export function keychainSigner<TConfig extends KeychainKitPluginConfig>(config: TConfig) {
    return async <TClient extends object>(client: TClient) => {
        const signer = await createClientSigner(config);
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
 *     keychainPayer({ backend: 'vault', vaultAddr, vaultToken, keyName }),
 * );
 * ```
 *
 * @see {@link keychainIdentity}
 * @see {@link keychainSigner}
 */
export function keychainPayer<TConfig extends KeychainKitPluginConfig>(config: TConfig) {
    return async <TClient extends object>(client: TClient) => {
        const payer = await createClientSigner(config);
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
 * Fordefi native manual mode is not accepted here: it requires the vault to
 * be the transaction fee payer, so install it with {@link keychainSigner} or
 * {@link keychainPayer} instead.
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
export function keychainIdentity(
    config: Exclude<KeychainKitPluginConfig, FordefiManualSignerConfig & { backend: 'fordefi' }>,
) {
    return async <TClient extends object>(client: TClient) => {
        assertServesAsIdentityAlone(config);
        const identity = await createClientSigner(config);
        return extendClient(client, { identity });
    };
}
