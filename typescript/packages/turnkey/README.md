# @solana/keychain-turnkey

Turnkey-based signer for Solana transactions using Turnkey's non-custodial key management API.

## Installation

```bash
pnpm add @solana/keychain-turnkey
```

## Prerequisites

1. A [Turnkey](https://turnkey.com) account
2. An organization with a Solana private key created
3. API credentials (public/private key pair) for authentication
4. Use the Turnkey dashboard or API to create a new private key with the `ED25519` curve type for Solana signing. Note the private key ID and the corresponding Solana public key (base58).

## Usage

### Basic Setup

```typescript
import { createTurnkeySigner } from '@solana/keychain-turnkey';

const signer = createTurnkeySigner({
    organizationId: 'your-organization-id',
    privateKeyId: 'your-turnkey-private-key-id',
    publicKey: 'your-solana-public-key-base58',
    apiPublicKey: 'your-api-public-key-hex',
    apiPrivateKey: 'your-api-private-key-hex',
});

// Check if the signer is available
const isAvailable = await signer.isAvailable();
console.log('Turnkey signer available:', isAvailable);
```

### Signing Transactions

```typescript
import { pipe } from '@solana/functional';
import { createTransaction } from '@solana/transactions';
import { signTransaction } from '@solana/signers';

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

## Configuration

### TurnkeySignerConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `organizationId` | `string` | Yes | Turnkey organization ID |
| `privateKeyId` | `string` | Yes | Turnkey private key ID to use for signing |
| `publicKey` | `string` | Yes | Solana public key (base58) corresponding to the Turnkey private key |
| `apiPublicKey` | `string` | Yes | Turnkey API public key (hex-encoded) for P256 authentication |
| `apiPrivateKey` | `string` | Yes | Turnkey API private key (hex-encoded) for P256 authentication |
| `apiBaseUrl` | `string` | No | Custom API base URL (default: `https://api.turnkey.com`) |
| `requestDelayMs` | `number` | No | Delay in ms between concurrent signing requests (default: 0) |

## How It Works

1. **Authentication**: Uses P256 ECDSA to sign API requests (X-Stamp header)
2. **Message Signing**: Sends raw payloads to Turnkey's `sign_raw_payload` endpoint
3. **Transaction Signing**: Uses Turnkey's `sign_transaction` endpoint with Solana-specific handling


## Security Considerations

1. **API Key Security**: Never hardcode API private keys. Use environment variables or secure secret management.
2. **Non-Custodial**: Turnkey manages key operations but you retain policy control over your keys.
3. **Policies**: Configure Turnkey policies to restrict signing operations as needed.

## License

MIT
