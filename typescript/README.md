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

All keychain signers implement the `SolanaSigner` interface from `@solana/keychain-core`, which is compatible with `@solana/signers` and `@solana/kit`:

```typescript
interface SolanaSigner<TAddress extends string = string> {
    readonly address: Address<TAddress>;
    signMessages(messages: SignableMessage[]): Promise<SignatureDictionary[]>;
    signTransactions(transactions: Transaction[]): Promise<SignatureDictionary[]>;
    isAvailable(): Promise<boolean>;
}
```

See the [`@solana/keychain` README](./packages/keychain/README.md) for more usage patterns.

### Using with Kit clients

`@solana/keychain-kit-plugin` installs a keychain signer on a [Kit client](https://github.com/anza-xyz/kit) as the `payer` and/or `identity`:

```typescript
import { createClient } from '@solana/kit';
import { keychainSigner } from '@solana/keychain-kit-plugin';

const client = await createClient().use(
    keychainSigner({ backend: 'privy', appId, appSecret, walletId }),
);

client.payer; // SolanaSigner — also a Kit TransactionSigner
```

## Signer capabilities

Backends come in three shapes, mirroring Kit's signer taxonomy. Most sign a transaction you own and hand back signatures (`SolanaSigner`). Managed-broadcast backends rewrite and broadcast the transaction themselves, so they expose only `signAndSendTransactions` (`SolanaSendingSigner`). Modifying backends rewrite the transaction — a fresh blockhash, managed fee instructions — and sign it but leave broadcasting to the caller, exposing only `modifyAndSignTransactions` (`SolanaModifyingSigner`); always continue from the transaction they return, never the one you passed in. Kit classifies signers by method presence, so each shape deliberately exposes exactly the transaction method it can honor.

| Backend | Interface | `signTransactions` | `modifyAndSignTransactions` | `signAndSendTransactions` | `signMessages` |
|---------|-----------|--------------------|-----------------------------|---------------------------|----------------|
| memory, vault, privy, turnkey, aws-kms, fireblocks, gcp-kms, dfns, para, openfort | `SolanaSigner` | yes | no | no | yes |
| cdp | `SolanaSigner` | yes | no | no | yes (UTF-8 payloads only) |
| utila | `SolanaSigner` | yes | no | no | throws at runtime |
| crossmint | `SolanaSendingSigner` | no | no | yes | not exposed |
| fordefi (black-box mode) | `SolanaSigner` | yes | no | no | yes |
| fordefi (native auto mode) | `SolanaSendingSigner` | no | no | yes | yes |
| fordefi (native manual mode) | `SolanaModifyingSigner` | no | yes | no | yes |

`signAndSendTransaction()` from `@solana/keychain-core` gets a transaction on chain through any of the three shapes. Signers that cannot broadcast use the send function you inject — core has no RPC dependency:

```typescript
import { signAndSendTransaction } from '@solana/keychain-core';

const signature = await signAndSendTransaction(signer, transaction, {
    sendTransaction: tx => sendAndConfirmTransaction(tx, { commitment: 'confirmed' }),
});
```

Every signing method — `signMessages`, `signTransactions`, `signAndSendTransactions` — takes Kit's optional config as its second argument, so `{ abortSignal }` cancels an in-flight signing request on any backend.

Use `signerCapabilities(signer)` to inspect a signer at runtime — it returns `{ canSignTransactions, canModifyAndSignTransactions, canSignMessages, canSignAndSend }`.

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
