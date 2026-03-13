# @solana/keychain-crossmint

Crossmint wallet signer for Solana transactions using Crossmint Wallets API.

## Installation

```bash
pnpm add @solana/keychain-crossmint
```

## Usage

```typescript
import { createCrossmintSigner } from '@solana/keychain-crossmint';

const signer = await createCrossmintSigner({
    apiKey: process.env.CROSSMINT_API_KEY!,
    walletLocator: process.env.CROSSMINT_WALLET_LOCATOR!,
});
```

## Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `apiKey` | `string` | Yes | - | Crossmint API key |
| `walletLocator` | `string` | Yes | - | Crossmint wallet locator |
| `apiBaseUrl` | `string` | No | `https://www.crossmint.com/api` | Base URL for Wallets API |
| `pollIntervalMs` | `number` | No | `1000` | Poll interval for managed transaction flow |
| `maxPollAttempts` | `number` | No | `60` | Max poll attempts before timeout |
| `signer` | `string` | No | - | Optional delegated signer locator |

## Behavior Notes

1. `signTransactions` uses a managed flow similar to Fireblocks `PROGRAM_CALL` style: create transaction, poll status, then extract a signature from Crossmint response data.
2. `signMessages` is intentionally unsupported and throws a signer error.

## License

MIT
