# @solana/keychain-utila

Utila wallet signer for Solana transactions.

```typescript
import { createUtilaSigner } from '@solana/keychain-utila';

const signer = await createUtilaSigner({
    serviceAccountEmail: process.env.UTILA_SERVICE_ACCOUNT_EMAIL!,
    serviceAccountPrivateKeyPem: process.env.UTILA_SERVICE_ACCOUNT_PRIVATE_KEY!,
    vaultId: process.env.UTILA_VAULT_ID!,
    walletId: process.env.UTILA_WALLET_ID!,
    network: process.env.UTILA_NETWORK ?? 'networks/solana-devnet',
});
```

The signer fetches the Solana address from the configured Utila wallet during initialization. Transaction signing uses Utila's serialized Solana transaction flow with `publish=false`, so callers remain responsible for broadcasting.

`signMessages` is intentionally unsupported because the Utila API surface used here does not expose a Solana message-sign initiation endpoint.

## Environment

```bash
UTILA_SERVICE_ACCOUNT_EMAIL=your-service-account@vault.utilaserviceaccount.io
UTILA_SERVICE_ACCOUNT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"
UTILA_VAULT_ID=your-vault-id
UTILA_WALLET_ID=your-wallet-id
UTILA_NETWORK=networks/solana-devnet
# UTILA_API_BASE_URL=https://api.utila.io
# UTILA_POLL_INTERVAL_MS=1000
# UTILA_MAX_POLL_ATTEMPTS=60
```
