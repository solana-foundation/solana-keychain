/** Solana network values accepted by the CDP sign endpoint. */
export type CdpNetwork = 'solana' | 'solana-devnet';

export interface CdpSignerConfig {
    /**
     * The Solana account address managed by CDP.
     */
    address: string;

    /**
     * Optional custom CDP API base URL.
     * Defaults to https://api.cdp.coinbase.com
     */
    baseUrl?: string;

    /**
     * CDP API key ID.
     * Used as the `apiKeyId` when authenticating with the CDP API.
     */
    cdpApiKeyId: string;

    /**
     * CDP API private key.
     * Base64-encoded Ed25519 key (64 bytes: seed || pubkey).
     * Used as the `apiKeySecret` when authenticating with the CDP API.
     */
    cdpApiKeySecret: string;

    /**
     * CDP Wallet Secret.
     * Required for signing operations (POST requests to signing endpoints).
     * A base64-encoded PKCS#8 DER EC (P-256) private key.
     */
    cdpWalletSecret: string;

    /**
     * Solana network the signed transaction targets, either `'solana'` or
     * `'solana-devnet'`. CDP requires it to resolve address lookup tables, so it is
     * mandatory for versioned transactions that carry any, and optional otherwise.
     */
    network?: CdpNetwork;

    /**
     * Optional delay in ms between concurrent signing requests to avoid rate limits.
     * Default: 0 (no delay)
     */
    requestDelayMs?: number;
}

/** Response from the CDP signMessage endpoint. */
export interface SignMessageResponse {
    /** Base58-encoded Ed25519 signature. */
    signature: string;
}

/** Response from the CDP signTransaction endpoint. */
export interface SignTransactionResponse {
    /** Base64-encoded signed wire transaction. */
    signedTransaction: string;
}

/** Response from the CDP getAccount endpoint. */
export interface AccountResponse {
    /** Solana account address (base58). */
    address: string;
}
