import type { Address } from '@solana/addresses';
import type {
    MessagePartialSigner,
    SignableMessage,
    SignatureDictionary,
    TransactionPartialSigner,
    TransactionSendingSigner,
} from '@solana/signers';
import type { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

/**
 * Unified signer interface that extends both transaction and message signers.
 * Provides both high-level (simple) and low-level (@solana/kit compatible) APIs.
 *
 * Each signer package exports a `createXSigner(config)` factory function as
 * the preferred way to construct instances.
 */
export interface SolanaSigner<TAddress extends string = string>
    extends TransactionPartialSigner<TAddress>, MessagePartialSigner<TAddress> {
    /**
     * Get the public key address of this signer
     */
    readonly address: Address<TAddress>;

    /**
     * Check if the signer is available and healthy.
     * For remote signers (Vault, Privy, Turnkey, AWS KMS, GCP KMS, Fireblocks, Dfns, Crossmint, CDP, Para, Openfort), this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;

    /**
     * Signs multiple messages and returns signature dictionaries
     * for @solana/kit signing compatibility.
     *
     * @param messages - Array of signable messages
     * @returns Array of signature dictionaries (address -> signature mapping)
     * @throws {SignerError} Implementations may throw `SIGNER_CONFIG_ERROR`, `SIGNER_HTTP_ERROR`,
     * `SIGNER_REMOTE_API_ERROR`, `SIGNER_PARSING_ERROR`, or `SIGNER_SIGNING_FAILED`.
     */
    signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]>;

    /**
     * Signs multiple transactions and returns signature dictionaries.
     * for @solana/kit signing compatibility.
     *
     * @param transactions - Array of transactions to sign
     * @returns Array of signature dictionaries (address -> signature mapping)
     * @throws {SignerError} Implementations may throw `SIGNER_CONFIG_ERROR`, `SIGNER_HTTP_ERROR`,
     * `SIGNER_REMOTE_API_ERROR`, `SIGNER_PARSING_ERROR`, or `SIGNER_SIGNING_FAILED`.
     */
    signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]>;
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
     * Get the public key address of this signer
     */
    readonly address: Address<TAddress>;

    /**
     * Check if the signer is available and healthy.
     * For remote signers, this performs an API health check.
     *
     * @throws {SignerError} Some implementations may throw for configuration or initialization errors.
     */
    isAvailable(): Promise<boolean>;
}
