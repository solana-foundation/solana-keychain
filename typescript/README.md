# @solana/keychain (TypeScript)

TypeScript packages for building custom Solana signers compatible with `@solana/kit` and `@solana/signers`

## Quick Example

```typescript
import { SolanaSigner } from '@solana/keychain-core';
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
| [@solana/keychain-core](./packages/core) | Core interfaces, types, and utilities for building custom signers |
| [@solana/keychain-privy](./packages/privy) | Privy wallet signer implementation |
| [@solana/keychain-turnkey](./packages/turnkey) | Turnkey wallet signer implementation |
| [@solana/keychain-vault](./packages/vault) | HashiCorp Vault signer implementation |
| [@solana/keychain-aws-kms](./packages/aws-kms) | AWS KMS signer implementation |
| [@solana/keychain-fireblocks](./packages/fireblocks) | Fireblocks signer implementation |
| [@solana/keychain-gcp-kms](./packages/gcp-kms) | Google Cloud KMS signer implementation |
| [@solana/keychain-cdp](./packages/cdp) | Coinbase Developer Platform (CDP) signer implementation |

## Installation

```bash
# Install the umbrella package (includes all signers)
pnpm add @solana/keychain

# Or install individual packages as needed
pnpm add @solana/keychain-core        # Core interfaces (required for custom signers)
pnpm add @solana/keychain-aws-kms     # AWS KMS signer
pnpm add @solana/keychain-cdp         # Coinbase Developer Platform (CDP) signer
pnpm add @solana/keychain-fireblocks  # Fireblocks signer
pnpm add @solana/keychain-gcp-kms    # Google Cloud KMS signer
pnpm add @solana/keychain-privy       # Privy signer
pnpm add @solana/keychain-turnkey     # Turnkey signer
pnpm add @solana/keychain-vault       # HashiCorp Vault signer
```

## CDP Signer Example

```typescript
import { CdpSigner } from '@solana/keychain-cdp';
import {
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';

// Create signer using CDP managed wallet infrastructure
// API keys are created at https://portal.cdp.coinbase.com
const signer = new CdpSigner({
    cdpApiKeyId: process.env.CDP_API_KEY_ID!,
    cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
    cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
    address: process.env.CDP_SOLANA_ADDRESS!,
    // baseUrl should be the host root (no "/platform" suffix)
    // baseUrl: 'https://api.cdp.coinbase.com',
});

// Build and sign a transaction
const transaction = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayerSigner(signer, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
);
const signed = await signTransactionMessageWithSigners(transaction);
```
