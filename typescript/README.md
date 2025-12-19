# @solana-keychain (TypeScript)

TypeScript packages for building custom Solana signers compatible with `@solana/kit` and `@solana/signers`

## Quick Example

```typescript
import { SolanaSigner } from '@solana-keychain/core';
import { signTransactionMessageWithSigners } from '@solana/signers';

class MyCustomSigner implements SolanaSigner {
    readonly address: Address;

    async isAvailable(): Promise<boolean> {
        return await myBackend.healthCheck();
    }

    async signTransactions(transactions) {
        return await myBackend.sign(transactions);
    }

    async signMessages(messages) {
        return await myBackend.signMessages(messages);
    }
}

const customSigner = new MyCustomSigner(config);
const transaction = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayerSigner(customSigner, tx),
    tx /* ... */
);
const signedTx = await signTransactionMessageWithSigners(transaction);
```
(see [test-signer.ts](./examples/test-signer.ts) for a complete example)

## Packages

| Package | Description |
|---------|-------------|
| [@solana-keychain/core](./packages/core) | Core interfaces, types, and utilities for building custom signers |
| [@solana-keychain/privy](./packages/privy) | Privy wallet signer implementation |
| [@solana-keychain/turnkey](./packages/turnkey) | Turnkey wallet signer implementation |
| [@solana-keychain/vault](./packages/vault) | HashiCorp Vault signer implementation |
| [@solana-keychain/aws-kms](./packages/aws-kms) | AWS KMS signer implementation |
| [@solana-keychain/fireblocks](./packages/fireblocks) | Fireblocks signer implementation |

## Installation

*note: not yet published to npm registry. must build locally to use*

```bash
# Core package (required for building custom signers)
pnpm add @solana-keychain/core

# Signer implementations
pnpm add @solana-keychain/aws-kms
pnpm add @solana-keychain/fireblocks
pnpm add @solana-keychain/privy
pnpm add @solana-keychain/turnkey
pnpm add @solana-keychain/vault
```
