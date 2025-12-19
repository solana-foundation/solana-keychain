# @solana/keychain-privy

Privy-based signer for Solana transactions using Privy's wallet API.

## Installation

```bash
pnpm add @solana/keychain-privy
```

## Usage

### Create and Initialize

```typescript
import { PrivySigner } from '@solana/keychain-privy';

// Create and initialize the signer (fetches public key from Privy API)
const signer = await PrivySigner.create({
    appId: 'your-privy-app-id',
    appSecret: 'your-privy-app-secret',
    walletId: 'user-wallet-id',
});

console.log('Signer address:', signer.address);
```

### Sign Messages

```typescript
import { createSignableMessage } from '@solana/signers';

const message = createSignableMessage('Hello, Privy!');
const [signatures] = await signer.signMessages([message]);
```

### Sign Transactions

```typescript
// Sign transactions using Privy's API
const [signatures] = await signer.signTransactions([transaction]);
```

### Check Availability

```typescript
const available = await signer.isAvailable();
console.log('Privy API available:', available);
```

## API Reference

### `PrivySigner.create(config)`

Creates and initializes a new PrivySigner instance.

**Config options:**

- `appId` (string, required): Your Privy application ID
- `appSecret` (string, required): Your Privy application secret
- `walletId` (string, required): The Privy wallet ID to use for signing
- `apiBaseUrl` (string, optional): Custom API base URL (defaults to `https://api.privy.io/v1`)
- `requestDelayMs` (number, optional): Delay in ms between concurrent signing requests to avoid rate limits (default: 0)

**Example:**

**Returns:** `Promise<PrivySigner>`

### Methods

- `signMessages(messages)`: Signs one or more messages
- `signTransactions(transactions)`: Signs one or more transactions
- `isAvailable()`: Checks if the Privy API is reachable
- `address`: Read-only property containing the signer's Solana address

## How It Works

1. **Initialization**: Fetches the wallet's public key from Privy API during creation
2. **Signing**: Sends transactions/messages to Privy's signing API endpoint
3. **Extraction**: Uses `extractSignatureFromWireTransaction` to extract signatures from Privy's response

## Security Notes

- Store your `appSecret` securely (use environment variables)
- Never expose your `appSecret` in client-side code
- This signer is intended for server-side use or secure environments
- Privy handles key management - your private keys never leave Privy's infrastructure
