/**
 * Configuration for creating an OpenfortSigner.
 *
 * Three required inputs:
 * 1. `secretKey` — Openfort project secret key (`sk_test_*` / `sk_live_*`).
 * 2. `accountId` — Backend wallet account ID (`acc_<uuid>`).
 * 3. `walletSecretPem` — PEM-encoded PKCS#8 ECDSA P-256 private key issued by
 *    the Openfort dashboard, used to sign the `x-wallet-auth` JWT.
 *
 * The wallet's Solana address is fetched automatically from
 * `GET /v1/accounts/{accountId}` during `create()`.
 */
export interface OpenfortSignerConfig {
    /** Openfort backend wallet account ID (`acc_<uuid>`). */
    accountId: string;

    /**
     * Optional custom Openfort API base URL.
     * Defaults to `https://api.openfort.io`.
     */
    baseUrl?: string;

    /**
     * Optional delay in ms between concurrent signing requests to avoid rate limits.
     * Default: 0 (no delay).
     */
    requestDelayMs?: number;

    /** Openfort project secret key (`sk_test_*` / `sk_live_*`). */
    secretKey: string;

    /**
     * PEM-encoded PKCS#8 ECDSA P-256 private key issued by the Openfort
     * dashboard. Used to sign the `x-wallet-auth` JWT on every request.
     */
    walletSecretPem: string;
}

/** Response from `GET /v1/accounts/{id}` — only the fields we need. */
export interface AccountResponse {
    /** Solana address (base58). */
    address: string;
}

/** Response from `POST /v2/accounts/backend/{id}/sign`. */
export interface SignResponse {
    /** Account ID that signed the data. */
    account: string;
    /** `"signature"`. */
    object: string;
    /** Hex-encoded signature with `0x` prefix. */
    signature: string;
}
