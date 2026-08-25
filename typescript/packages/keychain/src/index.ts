// Core types and utilities (flat export)
export * from '@solana/keychain-core';

// Unified signer factory, address resolver, and config union
export { createKeychainSigner } from './create-keychain-signer.js';
export { resolveAddress } from './resolve-address.js';
export type { BackendName, KeychainSignerConfig } from './types.js';

// Individual config types (flat re-exports)
export type { AwsKmsSignerConfig } from '@solana/keychain-aws-kms';
export type { CdpSignerConfig } from '@solana/keychain-cdp';
export type { CrossmintSendingSigner, CrossmintSignerConfig } from '@solana/keychain-crossmint';
export type { DfnsSignerConfig } from '@solana/keychain-dfns';
export type { FireblocksSignerConfig } from '@solana/keychain-fireblocks';
export type { FordefiNativeSigner, FordefiSignerConfig } from '@solana/keychain-fordefi';
export type { GcpKmsSignerConfig } from '@solana/keychain-gcp-kms';
export type { MemorySignerConfig } from '@solana/keychain-memory';
export type { OpenfortSignerConfig } from '@solana/keychain-openfort';
export type { ParaSignerConfig } from '@solana/keychain-para';
export type { PrivySignerConfig } from '@solana/keychain-privy';
export type { TurnkeySignerConfig } from '@solana/keychain-turnkey';
export type { UtilaSignerConfig } from '@solana/keychain-utila';
export type { VaultSignerConfig } from '@solana/keychain-vault';

// Signer implementations (namespaced to avoid conflicts)
export * as awsKms from '@solana/keychain-aws-kms';
export * as cdp from '@solana/keychain-cdp';
export * as crossmint from '@solana/keychain-crossmint';
export * as dfns from '@solana/keychain-dfns';
export * as fireblocks from '@solana/keychain-fireblocks';
export * as fordefi from '@solana/keychain-fordefi';
export * as gcpKms from '@solana/keychain-gcp-kms';
export * as memory from '@solana/keychain-memory';
export * as openfort from '@solana/keychain-openfort';
export * as para from '@solana/keychain-para';
export * as privy from '@solana/keychain-privy';
export * as turnkey from '@solana/keychain-turnkey';
export * as utila from '@solana/keychain-utila';
export * as vault from '@solana/keychain-vault';

// Re-export factory functions directly (preferred API)
export { createAwsKmsSigner } from '@solana/keychain-aws-kms';
export { createCdpSigner } from '@solana/keychain-cdp';
export { createCrossmintSigner } from '@solana/keychain-crossmint';
export { createDfnsSigner } from '@solana/keychain-dfns';
export { createFireblocksSigner } from '@solana/keychain-fireblocks';
export { createFordefiSigner } from '@solana/keychain-fordefi';
export { createGcpKmsSigner } from '@solana/keychain-gcp-kms';
export { createMemorySigner } from '@solana/keychain-memory';
export { createOpenfortSigner } from '@solana/keychain-openfort';
export { createParaSigner } from '@solana/keychain-para';
export { createPrivySigner } from '@solana/keychain-privy';
export { createTurnkeySigner } from '@solana/keychain-turnkey';
export { createUtilaSigner } from '@solana/keychain-utila';
export { createVaultSigner } from '@solana/keychain-vault';
