import type { MessagePartialSigner, TransactionPartialSigner, TransactionSendingSigner } from '@solana/signers';

/**
 * Unified signer interface that extends both transaction and message signers.
 *
 * `address`, `signMessages()` and `signTransactions()` come straight from the
 * Kit interfaces, so every keychain signer is usable anywhere Kit accepts a
 * partial signer. Both signing methods take Kit's optional config as their
 * second argument, including `{ abortSignal }` to cancel a signing request.
 *
 * Each signer package exports a `createXSigner(config)` factory function as
 * the preferred way to construct instances.
 *
 * @throws {SignerError} `signMessages()` and `signTransactions()` implementations
 * may throw `SIGNER_CONFIG_ERROR`, `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`,
 * `SIGNER_PARSING_ERROR`, or `SIGNER_SIGNING_FAILED`.
 */
export interface SolanaSigner<TAddress extends string = string>
    extends TransactionPartialSigner<TAddress>, MessagePartialSigner<TAddress> {
    /**
     * Check if the signer is available and healthy.
     * For remote signers (Vault, Privy, Turnkey, AWS KMS, GCP KMS, Fireblocks, Dfns, Crossmint, CDP, Para, Openfort), this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}

/**
 * Unified interface for managed-broadcast signers.
 *
 * A backend belongs in this category when it rewrites the transaction message
 * (e.g. gas sponsorship, its own blockhash or fees) and/or broadcasts
 * server-side, so its signature cannot be applied to the caller's transaction.
 * Such a backend must not expose `signTransactions` at all: Kit's signer
 * classification is duck-typed on method presence, and a present-but-throwing
 * method makes Kit partial-sign the transaction and fail at runtime. Use these
 * signers through `signAndSendTransactionMessageWithSigners()` (or
 * `signAndSendTransactions()` directly); the returned bytes identify the
 * transaction the provider landed.
 *
 * This interface deliberately does not include {@link MessagePartialSigner}.
 * Intersect it per backend only when the backend genuinely signs messages
 * (Fordefi native mode does; Crossmint does not).
 */
export interface SolanaSendingSigner<TAddress extends string = string> extends TransactionSendingSigner<TAddress> {
    /**
     * Check if the signer is available and healthy.
     * For remote signers, this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}
