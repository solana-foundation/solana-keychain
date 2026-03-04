# @solana/keychain

Unified Solana transaction signing for TypeScript applications. This umbrella package provides access to all keychain signers through a single import.

## Installation

```bash
pnpm add @solana/keychain
```

This installs all signer implementations. For a smaller bundle, install individual packages instead:

- `@solana/keychain-aws-kms` - AWS KMS signer
- `@solana/keychain-cdp` - Coinbase Developer Platform (CDP) signer
- `@solana/keychain-fireblocks` - Fireblocks signer
- `@solana/keychain-para` - Para MPC signer
- `@solana/keychain-privy` - Privy signer
- `@solana/keychain-turnkey` - Turnkey signer
- `@solana/keychain-vault` - HashiCorp Vault signer

## Usage

### Direct Signer Imports

The main signer classes are exported directly for convenience:

```typescript
import {
    AwsKmsSigner,
    FireblocksSigner,
    ParaSigner,
    PrivySigner,
    TurnkeySigner,
    VaultSigner,
} from '@solana/keychain';

// Use any signer directly
const signer = new VaultSigner({
    vaultAddr: 'https://vault.example.com',
    vaultToken: 'hvs.xxx',
    keyName: 'my-solana-key',
    publicKey: 'YourSolanaPublicKey',
});
```

### Namespaced Imports

Each signer package is also available under its namespace for accessing types and utilities:

```typescript
import { awsKms, fireblocks, para, privy, turnkey, vault } from '@solana/keychain';

// Access types
type VaultConfig = vault.VaultSignerConfig;
type FireblocksStatus = fireblocks.FireblocksTransactionStatus;

// Or use signers via namespace
const signer = new vault.VaultSigner({ ... });
```

### Core Utilities

Core types and utilities from `@solana/keychain-core` are re-exported:

```typescript
import { SignerErrorCode, SolanaSigner } from '@solana/keychain';

// Use error codes
try {
    await signer.signMessages([message]);
} catch (error) {
    if (error.code === SignerErrorCode.REMOTE_API_ERROR) {
        // Handle API error
    }
}
```

## Available Signers

| Signer |  Package |
|--------|----------|
| `AwsKmsSigner` | [@solana/keychain-aws-kms](../aws-kms/README.md) |
| `FireblocksSigner` | [@solana/keychain-fireblocks](../fireblocks/README.md) |
| `ParaSigner` | [@solana/keychain-para](../para/README.md) |
| `PrivySigner` | [@solana/keychain-privy](../privy/README.md) |
| `TurnkeySigner` | [@solana/keychain-turnkey](../turnkey/README.md) |
| `VaultSigner` | [@solana/keychain-vault](../vault/README.md) |

## Common Interface

All signers are compatible with the `@solana/kit` and `@solana/signers` libraries and implement the `SolanaSigner` interface:

```typescript
interface SolanaSigner<TAddress extends string = string> {
    readonly address: Address<TAddress>;
    signMessages(messages: SignableMessage[]): Promise<SignatureDictionary[]>;
    signTransactions(transactions: Transaction[]): Promise<SignatureDictionary[]>;
    isAvailable(): Promise<boolean>;
}
```

This allows you to write code that works with any signer:

```typescript
async function signAndSend(signer: SolanaSigner, transaction: Transaction) {
    const [signatures] = await signer.signTransactions([transaction]);
    // ... send transaction
}
```

## License

MIT
