# @solana/keychain-fordefi

[Fordefi](https://docs.fordefi.com/) MPC signer for Solana transactions, part of the [@solana/keychain](https://github.com/solana-foundation/solana-keychain) family.

## Installation

```bash
npm install @solana/keychain-fordefi
```

## Signing Modes

The signer supports two modes determined by whether `chain` is provided:

### Native Solana mode (recommended for on-chain use)

Set `chain` to use Fordefi's native Solana transaction type. Fordefi may modify the transaction (e.g. updating the blockhash or adding compute budget instructions) and broadcasts it on-chain automatically (`push_mode: 'auto'`). Use this with a **Solana vault**.

> **Note:** Native mode is a Kit `TransactionSendingSigner`, because Fordefi may sign a different message than the one supplied by the caller and broadcasts it itself. Use `signAndSendTransactionMessageWithSigners()` or `signAndSendTransactions()`. Calling the partial-signer method `signTransactions()` in native mode fails locally before any transaction is submitted.

```typescript
import { createFordefiSigner } from '@solana/keychain-fordefi';
import { signAndSendTransactionMessageWithSigners } from '@solana/signers';

const signer = await createFordefiSigner({
    accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
    vaultId: process.env.FORDEFI_VAULT_ID!,
    privateKeyPem: fs.readFileSync('./secret/private.pem', 'utf8'),
    publicKey: process.env.FORDEFI_PUBLIC_KEY!,
    chain: 'solana_devnet',
    fee: { type: 'custom', priority_fee: '1000' },
});

const transactionSignature = await signAndSendTransactionMessageWithSigners(transactionMessage);
```

Native auto-broadcast currently supports transactions whose only required signer is the configured Fordefi vault. Transactions requiring additional signers are rejected before submission until the integration forwards their partial signatures through Fordefi's `details.signatures` field.

### Black box mode

Omit `chain` to use Fordefi's `black_box_signature` type. Fordefi signs the raw bytes as-is and does **not** broadcast. The caller is responsible for assembling and submitting the transaction. Use this with a **black box vault**.

```typescript
const signer = await createFordefiSigner({
    accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
    vaultId: process.env.FORDEFI_BB_VAULT_ID!,
    privateKeyPem: fs.readFileSync('./secret/private.pem', 'utf8'),
    publicKey: process.env.FORDEFI_BB_PUBLIC_KEY!,
});
```

## Configuration

| Option | Required | Description |
|--------|----------|-------------|
| `accessToken` | Yes | Fordefi API bearer token |
| `vaultId` | Yes | Fordefi vault UUID |
| `privateKeyPem` | One of | PEM-encoded ECDSA P-256 private key for API request signing |
| `requestSigner` | One of | Custom API-request signer (e.g. KMS/HSM). Provide exactly one of `privateKeyPem` or `requestSigner` |
| `publicKey` | Yes | Solana public key of the vault (base58) |
| `chain` | No | `'solana_mainnet'` or `'solana_devnet'` — enables native Solana mode |
| `fee` | No | Priority fee config for native mode (e.g. `{ type: 'custom', priority_fee: '1000' }`) |
| `apiBaseUrl` | No | API base URL (default: `https://api.fordefi.com`) |
| `pollIntervalMs` | No | Polling interval in ms (default: 2000) |
| `maxPollAttempts` | No | Positive integer max polling attempts (default: 50) |
| `requestDelayMs` | No | Delay between concurrent requests in ms (default: 0) |
| `requestTimeoutMs` | No | Per-request HTTP timeout in ms (default: 30000) |

### Custom API-request signer (KMS/HSM)

Fordefi authenticates every POST with a request-level signature over
`{path}|{timestamp}|{body}` (ECDSA P-256, SHA-256, DER, base64). By default this is
computed locally from `privateKeyPem`. To keep that key in a KMS/HSM instead, implement
`FordefiRequestSigner` and pass it as `requestSigner` — `privateKeyPem` is then omitted.
`signRequest` must return base64 of the DER-encoded ECDSA P-256 signature over
`SHA-256(payload)`, and may be sync or async (AWS KMS `Sign` with `ECDSA_SHA_256` already
returns a DER signature — just base64-encode it).

```ts
import { createFordefiSigner, type FordefiRequestSigner } from '@solana/keychain-fordefi';

const kmsRequestSigner: FordefiRequestSigner = {
    async signRequest(payload) {
        // Sign SHA-256(payload) with your KMS (ECDSA P-256) and base64-encode the
        // returned DER signature. `payload` is `{path}|{timestamp}|{body}`.
        return await signWithKms(payload);
    },
};

const signer = await createFordefiSigner({
    accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
    vaultId: process.env.FORDEFI_VAULT_ID!,
    publicKey: process.env.FORDEFI_PUBLIC_KEY!,
    requestSigner: kmsRequestSigner, // instead of privateKeyPem
});
```

## Integration Tests

**`fordefi-signer.integration.test.ts`** exercises black box mode against the real Fordefi API and verifies the returned signatures with LiteSVM. It requires a **black box vault** (`FORDEFI_BB_VAULT_ID`, `FORDEFI_BB_PUBLIC_KEY`).

Required env vars (shared):

```
FORDEFI_ACCESS_TOKEN=<api-token>
FORDEFI_PRIVATE_KEY_PEM=<pem-content>
```

Black box vault:

```
FORDEFI_BB_VAULT_ID=<bb-vault-uuid>
FORDEFI_BB_PUBLIC_KEY=<bb-vault-address>
```

## License

MIT
