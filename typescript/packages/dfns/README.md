# @solana/keychain-dfns

Dfns-based signer for Solana transactions using [Dfns](https://dfns.co) Keys API.

## Installation

```bash
pnpm add @solana/keychain-dfns
```

## Prerequisites

1. A [Dfns](https://dfns.co) account with API access
2. A Solana wallet created in the Dfns dashboard
3. A service account with signing permissions

### Setting Up a Service Account

Follow the [Creating a Service
Account](https://docs.dfns.co/guides/developers/creating-a-service-account) guide:

1. **Generate a keypair** - https://docs.dfns.co/guides/developers/generate-a-key-pair#generate-a-key-pair
2. **Create the service account** in Settings > Developers > Service Accounts, pasting your public key
3. **Save the auth token** — it is only shown once. Store it securely along with your private key
4. **Configure permissions** — assign a role with minimal required permissions

You will need:
- **Auth token** (`authToken`) — the service account token
- **Credential ID** (`credId`) — shown in the service account details
- **Private key** (`privateKeyPem`) — the PEM key you generated in step 1
- **Wallet ID** (`walletId`) — found in the Dfns dashboard under Wallets

## Usage

### Basic Setup

```typescript
import { createDfnsSigner } from '@solana/keychain-dfns';

const signer = await createDfnsSigner({
    authToken: 'your-service-account-token',
    credId: 'your-credential-id',
    privateKeyPem: `-----BEGIN PRIVATE KEY-----
...your private key...
-----END PRIVATE KEY-----`,
    walletId: 'wa-xxxxx-xxxxx-xxxxx',
});

console.log('Signer address:', signer.address);
```

### Signing Transactions

```typescript
import {
    appendTransactionMessageInstructions,
    createSolanaRpc,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';

const rpc = createSolanaRpc('https://api.devnet.solana.com');
const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();

const message = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayerSigner(signer, tx),
    (tx) => appendTransactionMessageInstructions([/* your instructions */], tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
);

const signedTx = await signTransactionMessageWithSigners(message);
const encoded = getBase64EncodedWireTransaction(signedTx);
await rpc.sendTransaction(encoded).send();
```

### Signing Messages

```typescript
const message = new TextEncoder().encode('Hello, Solana!');
const [signatureDictionary] = await signer.signMessages([{ content: message }]);
```

## Configuration

### DfnsSignerConfig

| Field           | Type     | Required | Default                 | Description                                       |
|-----------------|----------|----------|-------------------------|---------------------------------------------------|
| `authToken`     | `string` | Yes      | -                       | Service account token or personal access token    |
| `credId`        | `string` | Yes      | -                       | Credential ID for user action signing             |
| `privateKeyPem` | `string` | Yes      | -                       | Private key in PEM format                         |
| `walletId`      | `string` | Yes      | -                       | Dfns wallet ID (starts with `wa-`)                |
| `apiBaseUrl`    | `string` | No       | `https://api.dfns.io`   | Custom API base URL                               |
| `requestDelayMs`| `number` | No       | `0`                     | Delay in ms between concurrent signing requests   |

## How It Works

1. **Initialization**: `create()` fetches the wallet from Dfns API and validates the Ed25519 public key
(your Solana address)
2. **Signing**: Transactions and messages are sent to the Dfns Keys API (`/keys/{keyId}/signatures`)
which returns Ed25519 signature components (r, s)
3. **User Action Signing**: Mutating API requests (like signing) go through a 3-step challenge/response
flow — the SDK handles this automatically using your `credId` and `privateKeyPem`

## Error Handling

The signer throws errors with specific codes from `@solana/keychain-core`:

- `CONFIG_ERROR` — Invalid configuration (missing fields, inactive wallet, unsupported key type)
- `REMOTE_API_ERROR` — Dfns API returned an error
- `SIGNING_FAILED` — Signature request failed or requires policy approval
- `PARSING_ERROR` — Failed to parse Dfns response

```typescript
import { SignerErrorCode } from '@solana/keychain-core';

try {
    await signer.signMessages([message]);
} catch (error) {
    if (error.code === SignerErrorCode.REMOTE_API_ERROR) {
        console.error('Dfns API error:', error.message);
    }
}
```

## Security Considerations

1. **Token Security**: Never hardcode auth tokens. Use environment variables or a secrets manager.
2. **Private Key**: Store the PEM private key securely. It is used to sign every user action requests.
3. **Policy Engine**: Configure [Dfns Policies](https://docs.dfns.co/api-reference/policies) to enforce
signing rules and approval workflows.
