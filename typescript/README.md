# @solana/keychain (TypeScript)

TypeScript packages for building custom Solana signers compatible with `@solana/kit` and `@solana/signers`

## Quick Example

```typescript
import { createKeychainSigner } from '@solana/keychain';
import { signTransactionWithSigners } from '@solana/signers'; // requires @solana/signers ≥ 6.5

// Create any signer via the unified factory
const signer = await createKeychainSigner({
    backend: 'privy',
    appId: 'your-app-id',
    appSecret: 'your-app-secret',
    walletId: 'your-wallet-id',
});

// Sign an already-compiled transaction
const signedTx = await signTransactionWithSigners([signer], compiledTransaction);
```

Or install an individual signer package for a smaller dependency footprint:

```typescript
import { createPrivySigner } from '@solana/keychain-privy';
import { signTransactionWithSigners } from '@solana/signers';

const signer = await createPrivySigner({
    appId: 'your-app-id',
    appSecret: 'your-app-secret',
    walletId: 'your-wallet-id',
});

const signedTx = await signTransactionWithSigners([signer], compiledTransaction);
```

`@solana/keychain-core` defines one capability interface per Kit signer shape, each adding `isAvailable(): Promise<boolean>` to the corresponding `@solana/signers` interface:

- `SolanaTransactionSigner` — Kit's `TransactionPartialSigner`: returns signatures for a caller-owned transaction.
- `SolanaModifyingSigner` — Kit's `TransactionModifyingSigner`: may rewrite the transaction before signing it. No backend has this shape yet.
- `SolanaSendingSigner` — Kit's `TransactionSendingSigner`: signs and broadcasts through its provider (managed broadcast).
- `SolanaMessageSigner` — Kit's `MessagePartialSigner`: signs off-chain messages. Orthogonal to the transaction shapes, exactly as Kit separates `MessageSigner` from `TransactionSigner`.

`SolanaSigner` is the union of the three transaction shapes — any keychain signer. Which shape a given signer has is not knowable from the union, so narrow with `isSolanaTransactionSigner()` / `isSolanaModifyingSigner()` / `isSolanaSendingSigner()` before calling a signing method. Most backends are `SolanaTransactionSigner & SolanaMessageSigner`, and every factory's return type states its backend's exact capabilities.

See the [`@solana/keychain` README](./packages/keychain/README.md) for more usage patterns.

### Using with Kit clients

`@solana/keychain-kit-plugin` installs a keychain signer on a [Kit client](https://github.com/anza-xyz/kit) as the `payer` and/or `identity`:

```typescript
import { createClient } from '@solana/kit';
import { keychainSigner } from '@solana/keychain-kit-plugin';

const client = await createClient().use(
    keychainSigner({ backend: 'privy', appId, appSecret, walletId }),
);

client.payer; // SolanaTransactionSigner — also a Kit TransactionPartialSigner
```

## Signer capabilities

Most backends sign a transaction you own and hand back signatures (`SolanaTransactionSigner`). Managed-broadcast backends rewrite and broadcast the transaction themselves, so they expose only `signAndSendTransactions` (`SolanaSendingSigner`) — Kit classifies signers by method presence, so they deliberately do not expose `signTransactions`. Message signing (`SolanaMessageSigner`) is an orthogonal capability: a backend that does not sign messages exposes no `signMessages` method at all.

| Backend | Shape | `signTransactions` | `signAndSendTransactions` | `signMessages` |
|---------|-------|--------------------|---------------------------|----------------|
| memory, vault, privy, turnkey, aws-kms, fireblocks, gcp-kms, dfns, para, openfort | `SolanaTransactionSigner & SolanaMessageSigner` | yes | no | yes |
| cdp | `SolanaTransactionSigner & SolanaMessageSigner` | yes | no | yes (UTF-8 payloads only) |
| utila | `SolanaTransactionSigner` | yes | no | no |
| crossmint | `SolanaSendingSigner` | no | yes | no |
| fordefi (black-box mode) | `FordefiBlackBoxSigner` (`SolanaTransactionSigner & SolanaMessageSigner`) | yes | no | yes |
| fordefi (native mode) | `FordefiNativeSigner` (`SolanaSendingSigner & SolanaMessageSigner`) | no | yes | yes |

`signAndSendTransaction()` from `@solana/keychain-core` gets a transaction on chain through any shape, routing by capability. Signers that cannot broadcast use the send function you inject — core has no RPC dependency:

```typescript
import { signAndSendTransaction } from '@solana/keychain-core';

const signature = await signAndSendTransaction(signer, transaction, {
    sendTransaction: tx => sendAndConfirmTransaction(tx, { commitment: 'confirmed' }),
});
```

Every signing method — `signMessages`, `signTransactions`, `signAndSendTransactions` — takes Kit's optional config as its second argument, so `{ abortSignal }` cancels an in-flight signing request on any backend.

Aborting stops waiting; it does not undo work a provider already accepted. On a backend that broadcasts (Crossmint, Fordefi native auto mode), an abort after the create call has been accepted is reported as `BROADCAST_UNCONFIRMED` with the provider transaction id and the abort reason kept as `cause`, because the transaction may already be on chain. Kit also re-checks the signal after a signer returns, so a signal that fires late can make the call site throw over a signature that was produced and, on a sending backend, a transaction that landed. Reconcile with the provider before retrying.

Use `signerCapabilities(signer)` to inspect a signer at runtime — it returns `{ canModifyTransactions, canSignAndSend, canSignMessages, canSignTransactions }`.

## Packages

| Package | Description |
|---------|-------------|
| [@solana/keychain-core](./packages/core) | Core interfaces, types, and utilities for building custom signers |
| [@solana/keychain-memory](./packages/memory) | In-memory keypair signer (local Ed25519 signing) |
| [@solana/keychain-privy](./packages/privy) | Privy wallet signer implementation |
| [@solana/keychain-turnkey](./packages/turnkey) | Turnkey wallet signer implementation |
| [@solana/keychain-vault](./packages/vault) | HashiCorp Vault signer implementation |
| [@solana/keychain-aws-kms](./packages/aws-kms) | AWS KMS signer implementation |
| [@solana/keychain-dfns](./packages/dfns) | Dfns wallet signer implementation |
| [@solana/keychain-fireblocks](./packages/fireblocks) | Fireblocks signer implementation |
| [@solana/keychain-gcp-kms](./packages/gcp-kms) | Google Cloud KMS signer implementation |
| [@solana/keychain-cdp](./packages/cdp) | Coinbase Developer Platform (CDP) signer implementation |
| [@solana/keychain-crossmint](./packages/crossmint) | Crossmint wallet signer implementation |
| [@solana/keychain-openfort](./packages/openfort) | Openfort backend wallet signer implementation |
| [@solana/keychain-para](./packages/para) | Para MPC signer implementation |
| [@solana/keychain-utila](./packages/utila) | Utila wallet signer implementation |
| [@solana/keychain-kit-plugin](./packages/kit-plugin) | Kit client plugins (`keychainSigner`/`keychainPayer`/`keychainIdentity`) |
| [@solana/keychain-fordefi](./packages/fordefi) | Fordefi MPC signer implementation |

## Installation

```bash
# Install the umbrella package (includes all signers)
pnpm add @solana/keychain

# Or install individual packages as needed
pnpm add @solana/keychain-core        # Core interfaces (required for custom signers)
pnpm add @solana/keychain-aws-kms     # AWS KMS signer
pnpm add @solana/keychain-cdp         # Coinbase Developer Platform (CDP) signer
pnpm add @solana/keychain-crossmint   # Crossmint signer
pnpm add @solana/keychain-dfns        # Dfns signer
pnpm add @solana/keychain-fireblocks  # Fireblocks signer
pnpm add @solana/keychain-gcp-kms    # Google Cloud KMS signer
pnpm add @solana/keychain-memory      # In-memory keypair signer (local)
pnpm add @solana/keychain-openfort    # Openfort backend wallet signer
pnpm add @solana/keychain-para        # Para MPC signer
pnpm add @solana/keychain-privy       # Privy signer
pnpm add @solana/keychain-turnkey     # Turnkey signer
pnpm add @solana/keychain-utila       # Utila signer
pnpm add @solana/keychain-vault       # HashiCorp Vault signer
pnpm add @solana/keychain-fordefi     # Fordefi signer

# Kit client plugins
pnpm add @solana/keychain-kit-plugin  # keychainSigner/keychainPayer/keychainIdentity
```
