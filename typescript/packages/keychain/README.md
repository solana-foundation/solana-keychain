# @solana/keychain

Unified Solana transaction signing for TypeScript applications. This umbrella package provides access to all keychain signers through a single import.

## Installation

```bash
pnpm add @solana/keychain
```

This installs all signer implementations. For a smaller bundle, install individual packages instead:

- `@solana/keychain-aws-kms` - AWS KMS signer
- `@solana/keychain-cdp` - Coinbase Developer Platform (CDP) signer
- `@solana/keychain-crossmint` - Crossmint signer
- `@solana/keychain-dfns` - Dfns signer
- `@solana/keychain-fireblocks` - Fireblocks signer
- `@solana/keychain-fordefi` - Fordefi MPC signer
- `@solana/keychain-gcp-kms` - GCP KMS signer
- `@solana/keychain-memory` - In-memory keypair signer (local Ed25519 signing)
- `@solana/keychain-openfort` - Openfort backend wallet signer
- `@solana/keychain-para` - Para MPC signer
- `@solana/keychain-privy` - Privy signer
- `@solana/keychain-turnkey` - Turnkey signer
- `@solana/keychain-utila` - Utila wallet signer
- `@solana/keychain-vault` - HashiCorp Vault signer

## Usage

### Unified Factory (Recommended)

Use `createKeychainSigner` with a discriminated config to create any backend:

```typescript
import { createKeychainSigner } from '@solana/keychain';

const signer = await createKeychainSigner({
    backend: 'privy',
    appId: 'your-app-id',
    appSecret: 'your-app-secret',
    walletId: 'your-wallet-id',
});

await signer.signTransactions([transaction]);
```

The `backend` field determines which signer is created. TypeScript narrows the config type automatically — you get full autocomplete for each backend's required fields, and the overloads return each backend's exact shape (see [Signer Shapes](#signer-shapes)).

**Managed-broadcast backends** (Crossmint always; Fordefi when `chain` enables native mode) rewrite the transaction and/or broadcast it server-side, so they return a `SolanaSendingSigner` (`CrossmintSendingSigner` / `FordefiNativeSigner`) with `signAndSendTransactions()` instead of `signTransactions()`:

```typescript
const crossmint = await createKeychainSigner({
    backend: 'crossmint',
    apiKey: '...',
    walletLocator: '...',
});

// Returns the signature identifying the transaction Crossmint landed.
const [signature] = await crossmint.signAndSendTransactions([transaction]);
```

With Kit, use `signAndSendTransactionMessageWithSigners()` for these backends; the partial-signer helpers below apply to every other backend.

### Resolve Address Without Signing

Use `resolveAddress` to get a signer's Solana address without initializing the full signing pipeline:

```typescript
import { resolveAddress } from '@solana/keychain';

// Sync backends (AWS KMS, GCP KMS, Turnkey, Vault, CDP) return instantly
const address = await resolveAddress({
    backend: 'vault',
    vaultAddr: 'https://vault.example.com',
    vaultToken: 'hvs.xxx',
    keyName: 'my-key',
    publicKey: '4Nd1m...',
});

// Async backends (Privy, Para, Fireblocks, Fordefi, Crossmint, Dfns, Utila) fetch from the API
const address2 = await resolveAddress({
    backend: 'privy',
    appId: '...',
    appSecret: '...',
    walletId: '...',
});
```

### Config Types

The `KeychainSignerConfig` discriminated union and individual config types are exported for building config management, CLIs, or dashboards:

```typescript
import type { KeychainSignerConfig, BackendName, PrivySignerConfig } from '@solana/keychain';

// BackendName = 'aws-kms' | 'cdp' | 'crossmint' | 'dfns' | 'fireblocks' | 'fordefi' | 'gcp-kms' | 'memory' | 'openfort' | 'para' | 'privy' | 'turnkey' | 'utila' | 'vault'

function loadConfig(json: unknown): KeychainSignerConfig {
    // Parse and validate your config...
}
```

### Signing a Compiled Transaction

If you already have a compiled transaction (e.g. from a dApp, backend service, or another system), use `signTransactionWithSigners` from `@solana/signers` (≥ 6.5) to sign it directly:

```typescript
import { signTransactionWithSigners } from '@solana/signers';
import { createKeychainSigner } from '@solana/keychain';

const signer = await createKeychainSigner({
    backend: 'vault',
    vaultAddr: 'https://vault.example.com',
    vaultToken: 'hvs.xxx',
    keyName: 'my-key',
    publicKey: '4Nd1m...',
});

// Sign an already-compiled transaction
const signedTx = await signTransactionWithSigners([signer], compiledTransaction);
```

This complements the message-level helpers (`signTransactionMessageWithSigners`) which extract signers from account metas automatically. The transaction-level variant is useful when signers aren't embedded in the transaction message.

### Direct Factory Imports

Each backend also exports its own factory function:

```typescript
import { createPrivySigner } from '@solana/keychain';

const signer = await createPrivySigner({
    appId: '...',
    appSecret: '...',
    walletId: '...',
});
```

### Namespaced Imports

Each signer package is available under its namespace for accessing types and utilities:

```typescript
import { fireblocks, vault } from '@solana/keychain';

type VaultConfig = vault.VaultSignerConfig;
type FireblocksStatus = fireblocks.FireblocksTransactionStatus;
```

### Core Utilities

Core types and utilities from `@solana/keychain-core` are re-exported:

```typescript
import { SignerErrorCode, type SolanaSigner } from '@solana/keychain';

try {
    await signer.signMessages([message]);
} catch (error) {
    if (error.code === SignerErrorCode.REMOTE_API_ERROR) {
        // Handle API error
    }
}
```

## Available Signers

| Backend | Package | Address Source |
|---------|---------|---------------|
| `aws-kms` | [@solana/keychain-aws-kms](../aws-kms/README.md) | Config (`publicKey`) |
| `cdp` | [@solana/keychain-cdp](../cdp/README.md) | Config (`address`) |
| `crossmint` | [@solana/keychain-crossmint](../crossmint/README.md) | API |
| `dfns` | [@solana/keychain-dfns](../dfns/README.md) | API |
| `fireblocks` | [@solana/keychain-fireblocks](../fireblocks/README.md) | API |
| `fordefi` | [@solana/keychain-fordefi](../fordefi/README.md) | API |
| `gcp-kms` | [@solana/keychain-gcp-kms](../gcp-kms/README.md) | Config (`publicKey`) |
| `memory` | [@solana/keychain-memory](../memory/README.md) | Derived from local keypair |
| `openfort` | [@solana/keychain-openfort](../openfort/README.md) | API |
| `para` | [@solana/keychain-para](../para/README.md) | API |
| `privy` | [@solana/keychain-privy](../privy/README.md) | API |
| `turnkey` | [@solana/keychain-turnkey](../turnkey/README.md) | Config (`publicKey`) |
| `utila` | [@solana/keychain-utila](../utila/README.md) | API |
| `vault` | [@solana/keychain-vault](../vault/README.md) | Config (`publicKey`) |

## Signer Shapes

`@solana/keychain-core` defines one capability interface per Kit signer shape, each adding `isAvailable(): Promise<boolean>`: `SolanaTransactionSigner` (Kit's `TransactionPartialSigner`), `SolanaModifyingSigner` (Kit's `TransactionModifyingSigner`), `SolanaSendingSigner` (Kit's `TransactionSendingSigner`), and the orthogonal `SolanaMessageSigner` (Kit's `MessagePartialSigner`). `SolanaSigner` is the union of the three transaction shapes — any keychain signer.

When the `backend` literal is known, `createKeychainSigner`'s overloads return the exact shape: `crossmint` → `CrossmintSendingSigner`, `fordefi` with `chain` set → `FordefiNativeSigner`, `utila` → `SolanaTransactionSigner` (no `signMessages`), and every other backend (including Fordefi black-box mode) → `SolanaTransactionSigner & SolanaMessageSigner`. With a widened `KeychainSignerConfig` — e.g. config loaded at runtime — the return type is the `SolanaSigner` union; narrow with `isSolanaTransactionSigner()` / `isSolanaSendingSigner()` from `@solana/keychain-core` before calling a signing method:

```typescript
import { isSolanaSendingSigner, isSolanaTransactionSigner } from '@solana/keychain-core';

const signer = await createKeychainSigner(loadConfig()); // SolanaSigner

if (isSolanaSendingSigner(signer)) {
    await signer.signAndSendTransactions([transaction]);
} else if (isSolanaTransactionSigner(signer)) {
    await signer.signTransactions([transaction]);
}
```

Managed-broadcast signers (Crossmint, Fordefi native mode) deliberately expose no `signTransactions`, because Kit classifies signers by method presence.

## License

MIT
