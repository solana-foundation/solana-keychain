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

## Packages

| Package | Description |
|---------|-------------|
| [@solana/keychain-core](./packages/core) | Core interfaces, types, and utilities for building custom signers |
| [@solana/keychain-privy](./packages/privy) | Privy wallet signer implementation |
| [@solana/keychain-turnkey](./packages/turnkey) | Turnkey wallet signer implementation |
| [@solana/keychain-vault](./packages/vault) | HashiCorp Vault signer implementation |
| [@solana/keychain-aws-kms](./packages/aws-kms) | AWS KMS signer implementation |
| [@solana/keychain-dfns](./packages/dfns) | Dfns wallet signer implementation |
| [@solana/keychain-fireblocks](./packages/fireblocks) | Fireblocks signer implementation |
| [@solana/keychain-gcp-kms](./packages/gcp-kms) | Google Cloud KMS signer implementation |
| [@solana/keychain-cdp](./packages/cdp) | Coinbase Developer Platform (CDP) signer implementation |
| [@solana/keychain-crossmint](./packages/crossmint) | Crossmint wallet signer implementation |
| [@solana/keychain-para](./packages/para) | Para MPC signer implementation |

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
pnpm add @solana/keychain-para        # Para MPC signer
pnpm add @solana/keychain-privy       # Privy signer
pnpm add @solana/keychain-turnkey     # Turnkey signer
pnpm add @solana/keychain-vault       # HashiCorp Vault signer
```
