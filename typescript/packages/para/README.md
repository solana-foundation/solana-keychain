# @solana/keychain-para

Para MPC signer for Solana transactions using Para's REST API.

## Installation

```bash
pnpm add @solana/keychain-para
```

## Prerequisites

1. A [Para](https://getpara.com) account with API access
2. A Para secret API key (server-side only, starts with `sk_`)
3. A Solana wallet created via the [Para REST API](https://docs.getpara.com/v2/rest/wallets/create-wallet) or dashboard

## Usage

### Create and Initialize

```typescript
import { createParaSigner } from '@solana/keychain-para';

// Create and initialize the signer (fetches public key from Para API)
const signer = await createParaSigner({
    apiKey: 'your-para-secret-key',
    walletId: 'your-para-wallet-id',
});

console.log('Signer address:', signer.address);
```

### Sign Messages

```typescript
import { createSignableMessage } from '@solana/signers';

const message = createSignableMessage('Hello, Para!');
const [signatures] = await signer.signMessages([message]);
```

### Sign Transactions

```typescript
// Sign transactions using Para's API
const [signatures] = await signer.signTransactions([transaction]);
```

### Check Availability

```typescript
const available = await signer.isAvailable();
console.log('Para wallet available:', available);
```

### With Rate Limiting

If you're signing multiple transactions/messages concurrently and want to avoid rate limits:

```typescript
const signer = await createParaSigner({
    apiKey: 'your-para-secret-key',
    walletId: 'your-para-wallet-id',
    requestDelayMs: 100, // 100ms delay between concurrent requests
});
```

## Configuration

### ParaSignerConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `apiKey` | `string` | Yes | Your Para secret API key (starts with `sk_`) |
| `walletId` | `string` | Yes | The Para wallet UUID to use for signing |
| `apiBaseUrl` | `string` | No | Custom API base URL (default: `https://api.getpara.com`) |
| `requestDelayMs` | `number` | No | Delay in ms between concurrent signing requests (default: 0) |

## How It Works

1. **Initialization**: Fetches the wallet's public key from Para's REST API during creation
2. **Signing**: Sends raw bytes (hex-encoded) to Para's `/v1/wallets/:walletId/sign-raw` endpoint
3. **Response**: Decodes the hex-encoded Ed25519 signature from Para's response

Para uses MPC (Multi-Party Computation) for key management — private keys are never assembled in a single location.

## Error Handling

The signer will throw errors with specific codes from `@solana/keychain-core`:

- `CONFIG_ERROR` - Invalid configuration (missing apiKey or walletId)
- `HTTP_ERROR` - Network request failed
- `REMOTE_API_ERROR` - Para API returned an error
- `PARSING_ERROR` - Failed to parse Para response

```typescript
import { SignerErrorCode } from '@solana/keychain-core';

try {
    await signer.signMessages([message]);
} catch (error) {
    if (error.code === SignerErrorCode.REMOTE_API_ERROR) {
        console.error('Para API error:', error.message);
    }
}
```

## Security Notes

- Store your secret key securely (use environment variables)
- Never expose your secret key in client-side code — it starts with `sk_` for a reason
- This signer is intended for server-side use or secure environments
- Para handles key management via MPC — your private keys never leave Para's infrastructure

## Resources

- [Para REST API Documentation](https://docs.getpara.com/v2/rest/overview)
- [Create a Wallet](https://docs.getpara.com/v2/rest/wallets/create-wallet)
- [Sign Raw Data](https://docs.getpara.com/v2/rest/wallets/sign-raw)

## License

MIT
