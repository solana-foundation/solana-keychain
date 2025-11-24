# @solana-keychain/vault

HashiCorp Vault-based signer for Solana transactions using Vault's transit engine.

## Installation

```bash
npm install @solana-keychain/vault
```

## Prerequisites

1. A HashiCorp Vault instance with the transit engine enabled
2. An ED25519 key created in the transit engine
3. A Vault token with sign permissions for the key

### Creating a Transit Key in Vault

```bash
# Enable the transit engine
vault secrets enable transit

# Create an ED25519 key
vault write transit/keys/my-solana-key type=ed25519

# Export the public key to get your Solana address
vault read -field=keys transit/export/signing-key/my-solana-key/1
```

## Usage

### Basic Setup

```typescript
import { VaultSigner } from '@solana-keychain/vault';

const signer = new VaultSigner({
    vaultAddr: 'https://vault.example.com',
    vaultToken: 'hvs.your-vault-token',
    keyName: 'my-solana-key',
    publicKey: 'your-solana-public-key-base58', // Must match the Vault key
});

// Check if the signer is available
const isAvailable = await signer.isAvailable();
console.log('Vault signer available:', isAvailable);
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

### With Rate Limiting

If you're signing multiple transactions/messages concurrently and want to avoid rate limits:

```typescript
const signer = new VaultSigner({
    vaultAddr: 'https://vault.example.com',
    vaultToken: 'hvs.your-vault-token',
    keyName: 'my-solana-key',
    publicKey: 'your-solana-public-key',
    requestDelayMs: 100, // 100ms delay between concurrent requests
});
```

## Configuration

### VaultSignerConfig

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vaultAddr` | `string` | Yes | Vault server address (e.g., https://vault.example.com) |
| `vaultToken` | `string` | Yes | Vault authentication token |
| `keyName` | `string` | Yes | Name of the transit key in Vault |
| `publicKey` | `string` | Yes | Solana public key (base58) corresponding to the Vault key |
| `requestDelayMs` | `number` | No | Delay in ms between concurrent signing requests (default: 0) |

## Vault Permissions

The Vault token must have the following permissions on the transit key:

```hcl
path "transit/sign/my-solana-key" {
  capabilities = ["update"]
}

path "transit/keys/my-solana-key" {
  capabilities = ["read"]
}
```

## Error Handling

The signer will throw errors with specific codes from `@solana-keychain/core`:

- `CONFIG_ERROR` - Invalid configuration
- `HTTP_ERROR` - Network request failed
- `REMOTE_API_ERROR` - Vault API returned an error
- `PARSING_ERROR` - Failed to parse Vault response

```typescript
import { SignerErrorCode } from '@solana-keychain/core';

try {
    await signer.signMessages([message]);
} catch (error) {
    if (error.code === SignerErrorCode.REMOTE_API_ERROR) {
        console.error('Vault API error:', error.message);
    }
}
```

## Security Considerations

1. **Token Security**: Never hardcode Vault tokens. Use environment variables or secure secret management.
2. **TLS**: Always use HTTPS when connecting to Vault.
3. **Token Rotation**: Implement token rotation and use short-lived tokens when possible.
4. **Audit Logging**: Enable Vault audit logging to track signing operations.

## License

MIT