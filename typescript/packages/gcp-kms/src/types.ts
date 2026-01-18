/**
 * Configuration for creating a GcpKmsSigner
 */
export interface GcpKmsSignerConfig {
    /** Full resource name of the crypto key version */
    keyName: string;
    /** Solana public key (base58-encoded) */
    publicKey: string;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
}
