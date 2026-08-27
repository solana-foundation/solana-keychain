import type {
    MessagePartialSigner,
    TransactionModifyingSigner,
    TransactionPartialSigner,
    TransactionSendingSigner,
} from '@solana/signers';

/**
 * A signer that returns signatures for a caller-owned transaction.
 *
 * `address` and `signTransactions()` come straight from Kit's
 * {@link TransactionPartialSigner}, so every keychain signer with this shape
 * is usable anywhere Kit accepts a partial signer. `signTransactions()` takes
 * Kit's optional config as its second argument, including `{ abortSignal }`
 * to cancel a signing request.
 *
 * Each signer package exports a `createXSigner(config)` factory function as
 * the preferred way to construct instances; the factory return type states
 * the backend's exact capabilities (most are
 * `SolanaTransactionSigner & SolanaMessageSigner`).
 *
 * @throws {SignerError} `signTransactions()` implementations may throw
 * `SIGNER_CONFIG_ERROR`, `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`,
 * `SIGNER_PARSING_ERROR`, or `SIGNER_SIGNING_FAILED`.
 */
export interface SolanaTransactionSigner<TAddress extends string = string> extends TransactionPartialSigner<TAddress> {
    /**
     * Check if the signer is available and healthy.
     * For remote signers (Vault, Privy, Turnkey, AWS KMS, GCP KMS, Fireblocks, Dfns, CDP, Para, Openfort, Utila), this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}

/**
 * A signer that may rewrite parts of the transaction before signing it, then
 * returns the modified transaction without broadcasting. Mirrors Kit's
 * {@link TransactionModifyingSigner}. No keychain backend has this shape yet.
 */
export interface SolanaModifyingSigner<TAddress extends string = string> extends TransactionModifyingSigner<TAddress> {
    /**
     * Check if the signer is available and healthy.
     * For remote signers, this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}

/**
 * A managed-broadcast signer.
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
 * This interface deliberately does not include {@link SolanaMessageSigner}.
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

/**
 * A signer that signs off-chain messages, mirroring Kit's
 * {@link MessagePartialSigner}.
 *
 * Message signing is a capability orthogonal to {@link SolanaSigner}, exactly
 * as Kit separates `MessageSigner` from `TransactionSigner`: a backend that
 * signs messages intersects this interface with its transaction shape
 * (`SolanaTransactionSigner & SolanaMessageSigner` for most backends), and a
 * backend that does not (Crossmint, Utila) exposes no `signMessages` method
 * at all rather than a throwing one.
 *
 * @throws {SignerError} `signMessages()` implementations may throw
 * `SIGNER_CONFIG_ERROR`, `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`,
 * `SIGNER_PARSING_ERROR`, or `SIGNER_SIGNING_FAILED`.
 */
export interface SolanaMessageSigner<TAddress extends string = string> extends MessagePartialSigner<TAddress> {
    /**
     * Check if the signer is available and healthy.
     * For remote signers, this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}

/**
 * Any keychain signer: the union over the transaction capabilities, mirroring
 * Kit's `TransactionSigner` union. Every backend can handle a transaction in
 * exactly one of these ways; which one is not knowable from this type, so
 * narrow with `isSolanaTransactionSigner()` / `isSolanaModifyingSigner()` /
 * `isSolanaSendingSigner()` (or hand the signer to `signAndSendTransaction()`,
 * which routes by capability) before calling a signing method.
 */
export type SolanaSigner<TAddress extends string = string> =
    SolanaModifyingSigner<TAddress> | SolanaSendingSigner<TAddress> | SolanaTransactionSigner<TAddress>;
