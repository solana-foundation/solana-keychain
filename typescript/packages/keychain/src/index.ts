// Core types and utilities (flat export)
export * from '@solana/keychain-core';

// Signer implementations (namespaced to avoid conflicts)
export * as awsKms from '@solana/keychain-aws-kms';
export * as cdp from '@solana/keychain-cdp';
export * as dfns from '@solana/keychain-dfns';
export * as fireblocks from '@solana/keychain-fireblocks';
export * as gcpKms from '@solana/keychain-gcp-kms';
export * as para from '@solana/keychain-para';
export * as privy from '@solana/keychain-privy';
export * as turnkey from '@solana/keychain-turnkey';
export * as vault from '@solana/keychain-vault';

// Re-export factory functions directly (preferred API)
export { createAwsKmsSigner } from '@solana/keychain-aws-kms';
export { createCdpSigner } from '@solana/keychain-cdp';
export { createDfnsSigner } from '@solana/keychain-dfns';
export { createFireblocksSigner } from '@solana/keychain-fireblocks';
export { createGcpKmsSigner } from '@solana/keychain-gcp-kms';
export { createParaSigner } from '@solana/keychain-para';
export { createPrivySigner } from '@solana/keychain-privy';
export { createTurnkeySigner } from '@solana/keychain-turnkey';
export { createVaultSigner } from '@solana/keychain-vault';
