# @solana/keychain-cdp

Coinbase Developer Platform (CDP) signer for Solana transactions using CDP's managed wallet infrastructure.

## Installation

```bash
pnpm add @solana/keychain-cdp
```

## Usage

### Create and Initialize

```typescript
import { createCdpSigner } from '@solana/keychain-cdp';

// API keys are created at https://portal.cdp.coinbase.com
const signer = await createCdpSigner({
    cdpApiKeyId: process.env.CDP_API_KEY_ID!,
    cdpApiKeySecret: process.env.CDP_API_KEY_SECRET!,
    cdpWalletSecret: process.env.CDP_WALLET_SECRET!,
    address: process.env.CDP_SOLANA_ADDRESS!,
});

console.log('Signer address:', signer.address);
```

### Sign Messages

```typescript
import { createSignableMessage } from '@solana/signers';

const message = createSignableMessage('Hello, CDP!');
const [signatures] = await signer.signMessages([message]);
```

### Sign Transactions

```typescript
import {
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';

const transaction = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayerSigner(signer, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight }, tx),
);
const signed = await signTransactionMessageWithSigners(transaction);
```

### Check Availability

```typescript
const available = await signer.isAvailable();
console.log('CDP API available:', available);
```

## API Reference

### `createCdpSigner(config)`

Creates and initializes a new CdpSigner instance.

**Config options:**

- `cdpApiKeyId` (string, required): CDP API key ID
- `cdpApiKeySecret` (string, required): Base64-encoded Ed25519 key (64 bytes: seed || pubkey)
- `cdpWalletSecret` (string, required): Base64-encoded PKCS#8 DER EC (P-256) private key
- `address` (string, required): Solana account address managed by CDP
- `baseUrl` (string, optional): Custom API base URL (defaults to `https://api.cdp.coinbase.com`)
- `requestDelayMs` (number, optional): Delay in ms between concurrent signing requests to avoid rate limits (default: 0)

**Returns:** `Promise<CdpSigner>`

### Methods

- `signMessages(messages)`: Signs one or more messages (UTF-8 strings only)
- `signTransactions(transactions)`: Signs one or more transactions
- `isAvailable()`: Checks if the CDP API is reachable
- `address`: Read-only property containing the signer's Solana address

## How It Works

1. **Initialization**: Validates Ed25519 API key (seed/pubkey match) and loads P-256 wallet key
2. **Authentication**: Every signing request sends two JWTs — an Ed25519 auth JWT and an ES256 wallet JWT with request body hash
3. **Signing**: Sends transactions/messages to CDP's signing API endpoint
4. **Extraction**: For transactions, uses `extractSignatureFromWireTransaction` to extract the signer's signature from CDP's signed wire transaction. For messages, decodes the base58-encoded signature directly from the response.

## Security Notes

- Store your `cdpApiKeySecret` and `cdpWalletSecret` securely (use environment variables)
- Never expose credentials in client-side code
- This signer is intended for server-side use or secure environments
- CDP handles key management — your signing keys never leave CDP's infrastructure
