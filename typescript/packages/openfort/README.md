# `@solana/keychain-openfort`

Openfort backend wallet signer for Solana transactions.

Calls Openfort's `POST /v2/accounts/backend/{accountId}/sign` endpoint with the
project secret key plus an `x-wallet-auth` ES256 JWT signed by the wallet
secret. The Solana address is fetched automatically from
`GET /v1/accounts/{accountId}` during signer initialization.

## Configuration

Three required inputs:

| Field             | Source                                     |
| ----------------- | ------------------------------------------ |
| `secretKey`       | Openfort project secret (`sk_test_*` / `sk_live_*`) |
| `accountId`       | Backend wallet account ID (`acc_<uuid>`)   |
| `walletSecretPem` | PEM PKCS#8 ECDSA P-256 private key from the Openfort dashboard |

## Usage

```ts
import { createOpenfortSigner } from '@solana/keychain-openfort';
import { signTransactionMessageWithSigners } from '@solana/transactions';

const signer = await createOpenfortSigner({
    accountId: process.env.OPENFORT_ACCOUNT_ID!,
    secretKey: process.env.OPENFORT_SECRET_KEY!,
    walletSecretPem: process.env.OPENFORT_WALLET_SECRET!,
});

const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
```
