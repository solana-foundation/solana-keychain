// Core types and utilities (flat export)
export * from '@solana/keychain-core';

// Signer implementations (namespaced to avoid conflicts)
export * as awsKms from '@solana/keychain-aws-kms';
export * as fireblocks from '@solana/keychain-fireblocks';
export * as privy from '@solana/keychain-privy';
export * as turnkey from '@solana/keychain-turnkey';
export * as vault from '@solana/keychain-vault';

// Re-export signer classes directly for convenience
export { AwsKmsSigner } from '@solana/keychain-aws-kms';
export { FireblocksSigner } from '@solana/keychain-fireblocks';
export { PrivySigner } from '@solana/keychain-privy';
export { TurnkeySigner } from '@solana/keychain-turnkey';
export { VaultSigner } from '@solana/keychain-vault';
