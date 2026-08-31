/**
 * Configuration for {@link createMemorySigner}.
 *
 * Exactly one of the source fields must be provided:
 * - {@link MemorySignerConfig.keyPair} — a pre-built `CryptoKeyPair` (e.g. from `@solana/keys`'s `generateKeyPair`)
 * - {@link MemorySignerConfig.privateKey} — raw bytes: 64-byte Solana CLI keypair (seed‖pubkey, validated) OR 32-byte Ed25519 seed (pubkey derived)
 * - {@link MemorySignerConfig.privateKeyString} — base58 string OR U8Array string `"[1, 2, ..., 64]"` (always 64 bytes)
 * - {@link MemorySignerConfig.privateKeyPath} — path to a Solana CLI keypair JSON file (Node-only)
 */
export interface MemorySignerConfig {
    keyPair?: CryptoKeyPair;
    /** Raw private key bytes — 64 bytes (Solana CLI: seed‖pubkey, validated) or 32 bytes (raw Ed25519 seed, pubkey derived). */
    privateKey?: Uint8Array;
    /** Path to a Solana CLI keypair JSON file. Node-only — uses dynamic `import('node:fs/promises')`. */
    privateKeyPath?: string;
    /** Base58 private key string OR U8Array string `"[1, 2, ..., 64]"`. */
    privateKeyString?: string;
}
