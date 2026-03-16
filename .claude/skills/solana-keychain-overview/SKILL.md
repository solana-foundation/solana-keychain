---
name: sf-solana-keychain-overview
description: >
  Architecture, usage, and capabilities of the solana-keychain library
  (Rust crate + TypeScript SDK). Use when someone asks "what is solana-keychain",
  "how does keychain work", "what signers are supported", "how do I use keychain",
  "show me keychain examples", "keychain architecture", "what backends are available",
  "how do I sign transactions with keychain", "keychain vs X", or needs to understand
  the library before working with it. Do NOT use for adding new signers — that's the
  add-signer skill.
---

# Solana Keychain Overview

Reference skill for understanding solana-keychain — what it is, how it's structured, and how to use it. For adding new signer backends, use the `add-signer` skill instead.

## What is solana-keychain

A unified signing library for Solana. One interface, multiple backends — swap between a local keypair, HashiCorp Vault, AWS KMS, Fireblocks, or any other supported provider without changing application code.

Available as:
- **Rust crate**: `solana-keychain` on crates.io
- **TypeScript SDK**: `@solana/keychain` on npm (plus individual `@solana/keychain-*` packages)

## When to use this skill

- Explaining what the library does to someone unfamiliar
- Answering "which signer should I use?" questions
- Showing usage examples (Rust or TypeScript)
- Describing the architecture or trait/interface system
- Comparing signers or understanding their tradeoffs

## Supported Backends

| Backend | Rust Feature | TS Package | Init Pattern | Key Storage |
|---------|-------------|------------|--------------|-------------|
| **Memory** | `memory` (default) | N/A | Sync constructor | Local keypair in memory |
| **HashiCorp Vault** | `vault` | `@solana/keychain-vault` | Sync (pubkey provided) | Vault Transit engine |
| **Privy** | `privy` | `@solana/keychain-privy` | Async init | Privy managed wallets |
| **Turnkey** | `turnkey` | `@solana/keychain-turnkey` | Sync (pubkey provided) | Turnkey infrastructure |
| **AWS KMS** | `aws_kms` | `@solana/keychain-aws-kms` | Async constructor | AWS KMS EdDSA key |
| **Fireblocks** | `fireblocks` | `@solana/keychain-fireblocks` | Async init | Fireblocks vault |
| **GCP KMS** | `gcp_kms` | `@solana/keychain-gcp-kms` | Async constructor | GCP Cloud KMS EdDSA key |
| **Dfns** | `dfns` | `@solana/keychain-dfns` | Async init | Dfns wallet infrastructure |
| **CDP** | N/A | `@solana/keychain-cdp` | Async | Coinbase Developer Platform |
| **Para** | `para` | `@solana/keychain-para` | Async init | Para MPC wallets |

## Architecture

### Rust

The core abstraction is the `SolanaSigner` trait in `rust/src/traits.rs`:

```rust
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    fn pubkey(&self) -> Pubkey;
    async fn sign_transaction(&self, tx: &mut Transaction) -> Result<SignedTransaction, SignerError>;
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
    async fn sign_partial_transaction(&self, tx: &mut Transaction) -> Result<SignedTransaction, SignerError>;
    async fn is_available(&self) -> bool;
}
```

A unified `Signer` enum in `rust/src/lib.rs` wraps all backends, enabling runtime backend selection:

```rust
let signer = Signer::from_memory("base58-private-key")?;
// or
let signer = Signer::from_vault(vault_addr, vault_token, key_name, pubkey)?;
// or
let signer = Signer::from_aws_kms(key_id, region).await?;
```

All variants implement `SolanaSigner`, so consuming code is backend-agnostic.

**Feature flags** control which backends are compiled in. Only `memory` is enabled by default. Use `--features all` to include everything, or pick individual features.

### TypeScript

The core abstraction is the `SolanaSigner<TAddress>` interface in `@solana/keychain-core`:

```typescript
interface SolanaSigner<TAddress extends string = string>
    extends TransactionPartialSigner<TAddress>, MessagePartialSigner<TAddress> {
    readonly address: Address<TAddress>;
    isAvailable(): Promise<boolean>;
    signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]>;
    signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]>;
}
```

This extends `@solana/signers` interfaces, making every keychain signer directly compatible with `@solana/kit`.

**Package structure**: Each signer is its own npm package (`@solana/keychain-privy`, `@solana/keychain-vault`, etc.) for tree-shaking. The umbrella `@solana/keychain` re-exports everything.

**Preferred API**: Factory functions like `createPrivySigner()`, `createVaultSigner()`, etc. Class-based constructors are deprecated.

## Usage Examples

### Rust

```rust
use solana_keychain::{Signer, SolanaSigner};

// Create a signer (runtime selection)
let signer = Signer::from_vault(
    "https://vault.example.com",
    "hvs.token",
    "solana-key",
    "YourSolanaPublicKeyBase58",
)?;

// Sign a transaction
let (signed_tx_base64, signature) = signer.sign_transaction(&mut tx).await?;

// Sign a message
let signature = signer.sign_message(b"hello").await?;

// Health check
let available = signer.is_available().await?;
```

### TypeScript

```typescript
import { createPrivySigner } from '@solana/keychain-privy';

const signer = await createPrivySigner({
    appId: 'your-app-id',
    appSecret: 'your-secret',
    walletId: 'wallet-id',
});

// Compatible with @solana/kit
import { signTransactionMessageWithSigners } from '@solana/signers';
const signedTx = await signTransactionMessageWithSigners(transaction);

// Or sign directly
const [signatureDict] = await signer.signTransactions([transaction]);

// Health check
const available = await signer.isAvailable();
```

## Error Handling

Both implementations use a centralized error type:

- **Rust**: `SignerError` enum in `rust/src/error.rs` — covers key format, signing failure, remote API, serialization, and config errors
- **TypeScript**: `SignerError` class with `SignerErrorCode` enum in `@solana/keychain-core` — codes include `CONFIG_ERROR`, `SIGNING_FAILED`, `REMOTE_API_ERROR`, `HTTP_ERROR`, `NOT_AVAILABLE`

## Testing

Both Rust and TypeScript use mocked HTTP endpoints for unit tests (no real API calls):
- **Rust**: `wiremock` crate
- **TypeScript**: Mocked `fetch` via `vitest`

Integration tests exist for each backend (require real credentials via env vars).

For detailed file locations and test commands, see the project's `CLAUDE.md`.

