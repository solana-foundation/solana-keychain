# @solana/keychain-fireblocks

Fireblocks-based signer for Solana transactions using Fireblocks' institutional custody API.

## Installation

```bash
pnpm add @solana/keychain-fireblocks
```

## Prerequisites

1. A [Fireblocks](https://fireblocks.com) account with API access
2. A vault account with Solana (SOL) asset configured
3. An API user with signing permissions and RSA 4096 private key

Follow the [Fireblocks documentation](https://developers.fireblocks.com/docs/create-direct-custody-wallets) to get started.

## Usage

### Basic Setup

```typescript
import { createFireblocksSigner } from '@solana/keychain-fireblocks';

const signer = await createFireblocksSigner({
    apiKey: 'your-fireblocks-api-key',
    privateKeyPem: `-----BEGIN PRIVATE KEY-----
...your RSA 4096 private key...
-----END PRIVATE KEY-----`,
    vaultAccountId: '0',
});

console.log('Signer address:', signer.address);
```

### Signing Transactions

```typescript
import { pipe, signTransaction, createTransaction } from '@solana/kit';

// Create your transaction
const transaction = pipe(
    createTransaction({ version: 0 }),
    // ... add instructions
);

// Sign the transaction
const signedTransaction = await signTransaction([signer], transaction);
```

### Signing Messages

```typescript
import { signMessage } from '@solana/signers';

const message = new TextEncoder().encode('Hello, Solana!');
const signature = await signMessage([signer], message);
```

### Signing Mode

By default the signer uses Fireblocks **RAW signing**: it signs the message bytes and returns the signature to you, and you broadcast the transaction yourself.

With `useProgramCall: true`, transactions are signed with the **PROGRAM_CALL** operation instead, sent with `signOnly: true` and `useDurableNonce: false` so Fireblocks signs the submitted transaction without broadcasting it and without rewriting the message. The returned signature is verified against the vault address over the local message bytes before it is used, and you still broadcast yourself. `signMessages()` always uses RAW, since PROGRAM_CALL only accepts serialized transactions.

PROGRAM_CALL accepts legacy and v0 messages only, requires a hot wallet, and must be enabled for your workspace by Fireblocks. If Fireblocks broadcasts anyway (a workspace that ignores `signOnly`), signing rejects with `BROADCAST_UNCONFIRMED` carrying the provider transaction id rather than reporting a plain failure. A PROGRAM_CALL whose outcome the poll never resolves, because the attempt budget ran out or the poll requests themselves failed, reports the same code and id: the request exists on Fireblocks and only its outcome is unknown, so check it there before retrying.

### With Devnet

```typescript
const signer = await createFireblocksSigner({
    apiKey: 'your-fireblocks-api-key',
    privateKeyPem: '...',
    vaultAccountId: '0',
    assetId: 'SOL_TEST', // Use devnet asset
});
```

## Configuration

### FireblocksSignerConfig

| Field             | Type      | Required | Default                     | Description                                                                                                                                                                                                |
| ----------------- | --------- | -------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apiKey`          | `string`  | Yes      | -                           | Fireblocks API key (X-API-Key header)                                                                                                                                                                      |
| `privateKeyPem`   | `string`  | Yes      | -                           | RSA 4096 private key in PEM format for JWT signing                                                                                                                                                         |
| `vaultAccountId`  | `string`  | Yes      | -                           | Fireblocks vault account ID                                                                                                                                                                                |
| `apiBaseUrl`      | `string`  | No       | `https://api.fireblocks.io` | Custom API base URL                                                                                                                                                                                        |
| `assetId`         | `string`  | No       | `SOL`                       | Asset ID (`SOL` for mainnet, `SOL_TEST` for devnet)                                                                                                                                                        |
| `pollIntervalMs`  | `number`  | No       | `1000`                      | Polling interval in ms when waiting for transaction completion                                                                                                                                             |
| `maxPollAttempts` | `number`  | No       | `60`                        | Maximum polling attempts before timeout                                                                                                                                                                    |
| `requestDelayMs`  | `number`  | No       | `0`                         | Delay in ms between signing requests (a gap between items in `useProgramCall` mode, which batches sequentially)                                                                                                                                                            |
| `useProgramCall`  | `boolean` | No       | `false`                     | Sign transactions with PROGRAM_CALL (`signOnly`) instead of RAW — see [Signing Mode](#signing-mode)                                                                                                        |

## How It Works

1. **Initialization**: Fetches the vault account's Solana address from Fireblocks API
2. **JWT Authentication**: Signs API requests with RS256 JWT using your RSA private key
3. **Transaction Creation**: Creates a RAW signing transaction in Fireblocks, or a sign-only PROGRAM_CALL when `useProgramCall` is set
4. **Signature Extraction**: Extracts the Ed25519 signature from the completed transaction/message

## Security Considerations

1. **Private Key Security**: The RSA private key should never be committed to source control. Use environment variables or secure secret management.
2. **API Key Rotation**: Rotate API keys periodically according to your security policy.
3. **Policy Engine**: Configure Fireblocks Transaction Authorization Policy (TAP) to enforce signing rules.

## License

MIT
