# Migrating to 2.0

Covers the upgrade from `solana-keychain` 1.4.0 (Rust) and `@solana/keychain*` 1.4.0 (TypeScript) to 2.0.0. The theme of the release: a backend's transaction shape is now a compile-time fact. `SolanaSigner` keeps identity, message signing and health; transaction handling moved to one capability per backend (sign, rewrite-and-sign, or sign-and-broadcast). The [security model](SECURITY_MODEL.md) explains why the shapes differ. A pre-release is available as `2.0.0-beta.1`: `cargo add solana-keychain@2.0.0-beta.1`, `npm install @solana/keychain-core@beta`.

## Rust

### The trait split

`sign_transaction` is no longer on `SolanaSigner`. Backends that sign the caller's bytes implement `TransactionSigner`; backends whose provider rewrites the transaction before signing implement `ModifyingSigner` (`modify_and_sign_transaction`); backends whose provider broadcasts implement `SendingSigner` (`sign_and_send_transaction`). Each backend implements exactly one.

Before:

```rust
use solana_keychain::{Signer, SolanaSigner};

let result = signer.sign_transaction(&mut tx).await?;
```

After, for a concrete backend, import the capability trait:

```rust
use solana_keychain::{MemorySigner, TransactionSigner};

let result = signer.sign_transaction(&mut tx).await?;
```

Trait objects follow: a `Box<dyn SolanaSigner>` that was used for transaction signing becomes `Box<dyn TransactionSigner>`.

### The `Signer` umbrella routes by capability

The `Signer` enum implements only the base trait (`pubkey`, `sign_message`, `is_available`). To sign a transaction, narrow first, or let `sign_and_send` route for you:

```rust
if let Some(transaction_signer) = signer.as_transaction_signer() {
    let result = transaction_signer.sign_transaction(&mut tx).await?;
}
```

`as_transaction_signer()`, `as_modifying_signer()` and `as_sending_signer()` return `None` when the backend does not have that shape. For the common sign-then-broadcast flow, `Signer::sign_and_send` works with every shape; the crate has no RPC client, so you supply the network hop:

```rust
let signature = signer
    .sign_and_send(&mut tx, |encoded| async move { broadcast(encoded).await })
    .await?;
```

### Transactions are versioned

`sign_transaction` takes `&mut VersionedTransaction` instead of `&mut Transaction`. Convert a legacy transaction at the call site with `.into()`. Legacy and v0 work on every SDK feature; v1 transactions require `sdk-v4`.

### Crossmint is sending-only

Crossmint's API has no sign-only path: an approved transaction is always executed server-side. In 1.x `sign_transaction` silently submitted and polled; it now fails. Call `sign_and_send_transaction` instead:

```rust
use solana_keychain::SendingSigner;

let signature = crossmint.sign_and_send_transaction(&tx).await?;
```

It returns the signature identifying the landed transaction and leaves your transaction untouched. Crossmint also no longer signs off-chain messages: `sign_message` fails.

### New error variant: `BroadcastUnconfirmed`

`SignerError::BroadcastUnconfirmed { provider_tx_id, .. }` is the terminal state for "the provider may have executed this". Exhaustive matches on `SignerError` need a new arm. Do not blindly retry it: reconcile against `provider_tx_id` when present; when absent, only a byte-identical resend is safe.

## TypeScript

### Kit 8 peer dependencies

All packages now require `@solana/*` >= 8.0.0 (previously >= 6.0.1). Upgrade `@solana/kit` and friends first.

### `SolanaSigner` is now a capability union

The single interface with both `signTransactions` and `signMessages` is gone. `SolanaSigner` is now `SolanaTransactionSigner | SolanaModifyingSigner | SolanaSendingSigner`, and message signing is the separate, orthogonal `SolanaMessageSigner`. A backend exposes only the methods it supports; there are no throwing stubs, because Kit classifies signers by method presence.

Before:

```ts
import type { SolanaSigner } from '@solana/keychain-core';

async function pay(signer: SolanaSigner) {
    const [signatures] = await signer.signTransactions([transaction]);
}
```

After, narrow with a guard:

```ts
import { isSolanaTransactionSigner } from '@solana/keychain-core';

if (isSolanaTransactionSigner(signer)) {
    const [signatures] = await signer.signTransactions([transaction]);
}
```

The guards are `isSolanaTransactionSigner`, `isSolanaModifyingSigner`, `isSolanaSendingSigner` and `isSolanaMessageSigner`; `signerCapabilities(signer)` reports all four at once. Or skip narrowing entirely with the new core helper, which routes by capability:

```ts
import { signAndSendTransaction } from '@solana/keychain-core';

const signature = await signAndSendTransaction(signer, transaction, {
    sendTransaction: tx => sendAndConfirmTransaction(tx, { commitment: 'confirmed' }),
});
```

`signTransactions`, `signMessages` and `signAndSendTransactions` now accept Kit's optional config as a second argument, including `{ abortSignal }`.

### The class tier is gone

Backend signer classes, their static `create()` methods and `FireblocksSigner.init()` are no longer exported; the `createXxxSigner()` factories are the only way to construct a signer. `ApiKeyStamper` is no longer exported from `@solana/keychain-turnkey`.

Before:

```ts
const signer = await PrivySigner.create(config);
```

After:

```ts
const signer = await createPrivySigner(config);
```

### Crossmint is sending-only

`createCrossmintSigner()` returns a `SolanaSendingSigner`: `signAndSendTransactions` only, no `signTransactions`, no `signMessages`. `@solana/keychain-kit-plugin` now rejects `{ backend: 'crossmint' }` at the type level and at runtime, because a managed-broadcast signer cannot serve as a Kit client `payer`/`identity`; create it with `createKeychainSigner()` and use `signAndSendTransaction()` instead.

### New error code: `BROADCAST_UNCONFIRMED`

Same semantics as the Rust variant: the provider may have executed the transaction. `providerMayHaveAccepted()` and `providerStatus()` on the error help classify before retrying.

## New in 2.0

- Fordefi backend, in three fixed-at-construction modes: black box (sign-only, `chain` unset), native auto (`chain` set, provider broadcasts) and native manual (`chain` set, `push_mode`/`pushMode` manual: the provider rewrites and signs, you broadcast). Native manual is the one `ModifyingSigner`/`SolanaModifyingSigner`: continue from the transaction it returns, never the one you submitted.
- v1 transaction support (SIMD-0385) across signing paths; Rust gates it behind `sdk-v4`.
- One-call sign-and-send in both languages: `Signer::sign_and_send` / `sign_and_send` (Rust) and `signAndSendTransaction` (TypeScript).
