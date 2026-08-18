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

1. Crossmint executes transactions server-side and sponsors gas, which makes it the fee payer, so the message it signs generally differs from the one you submitted. Use `signAndSendTransactions()` (or `signAndSendTransactionMessageWithSigners()`): the returned value is the landed transaction's fee-payer signature, the identifier you can pass to `getTransaction`/`confirmTransaction`, not a signature over your message bytes. Under sponsorship the fee payer is Crossmint's sponsor key; your wallet's own signature is verified internally before the identifier is returned.
2. `signTransactions` rejects with `SIGNER_CONFIG_ERROR`. A signature dictionary would claim to cover your message, which it does not.
3. `signMessages` is intentionally unsupported and throws a signer error.

```typescript
const [signature] = await signer.signAndSendTransactions([transaction]);
```

## License

MIT
