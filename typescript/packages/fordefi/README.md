# @solana/keychain-fordefi

[Fordefi](https://docs.fordefi.com/) MPC signer for Solana transactions, part of the [@solana/keychain](https://github.com/solana-foundation/solana-keychain) family.

## Installation

```bash
npm install @solana/keychain-fordefi
```

## Signing Modes

The signer supports three modes determined by `chain` and `pushMode`:

### Native auto mode (recommended for managed broadcasting)

Set `chain` to use Fordefi's native Solana transaction type. Fordefi may modify the transaction (e.g. updating the blockhash or adding compute budget instructions) and broadcasts it on-chain automatically (`push_mode: 'auto'`). Use this with a **Solana vault**.

> **Note:** Native mode is a Kit `TransactionSendingSigner` (`FordefiNativeSigner`, built on `SolanaSendingSigner` from `@solana/keychain-core`), because Fordefi may sign a different message than the one supplied by the caller and broadcasts it itself. Use `signAndSendTransactionMessageWithSigners()` or `signAndSendTransactions()`. Native instances expose **no** `signTransactions` — Kit classifies signers by method presence, so its absence is what routes the signer through Kit's sending flow — but message signing (`signMessages`) still works. Black-box instances are the mirror image: `signTransactions` and no `signAndSendTransactions`.

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

### Native manual mode

Set `chain` and `pushMode: 'manual'` to let Fordefi replace the recent blockhash and manage `SetComputeUnitPrice`/`SetComputeUnitLimit`, then sign the transaction while leaving broadcasting to the caller. Every other message field is validated exactly. Custom unit prices must match and custom priority fees cap the effective returned fee. This returns a Kit `TransactionModifyingSigner` (`FordefiNativeManualSigner`) with `modifyAndSignTransactions()` and no `signTransactions()` or `signAndSendTransactions()`.

A priority fee Fordefi introduces on its own initiative is capped at `DEFAULT_MAX_PRIORITY_FEE_LAMPORTS` (0.1 SOL), so a compromised or malfunctioning response cannot drain the fee payer. Set `maxPriorityFeeLamports` to raise or lower that ceiling; a custom `priority_fee` governs instead when set. The ceiling never applies to a compute-unit price the caller placed in the transaction themselves, since those requests are validated byte-for-byte.

The two fee instructions are asymmetric by design. A compute-unit *price* you set yourself is protected: the whole message is then compared byte-for-byte, so Fordefi can only replace the blockhash. A compute-unit *limit* you set with no price is **not** preserved — Fordefi manages the limit in manual mode, and the returned limit is only bounded indirectly, through the lamport ceiling above. Set a compute-unit price alongside your limit if you need the limit held exactly.

Fordefi must be the transaction fee payer and must sign before any other signer. The validated transaction retains unsigned slots for downstream partial signers, which can sign the blockhash-updated message before the caller submits it.

```typescript
import { createFordefiSigner } from '@solana/keychain-fordefi';
import { partiallySignTransactionWithSigners } from '@solana/signers';

const signer = await createFordefiSigner({
    accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
    vaultId: process.env.FORDEFI_VAULT_ID!,
    privateKeyPem: fs.readFileSync('./secret/private.pem', 'utf8'),
    publicKey: process.env.FORDEFI_PUBLIC_KEY!,
    chain: 'solana_devnet',
    pushMode: 'manual',
});

const [fordefiSignedTransaction] = await signer.modifyAndSignTransactions([transaction]);
const fullySignedTransaction = await partiallySignTransactionWithSigners(
    remainingSigners,
    fordefiSignedTransaction,
);
// Broadcast fullySignedTransaction through your RPC client.
```

Fordefi may replace the recent blockhash immediately before signing. Its response does not include that blockhash's exact `lastValidBlockHeight`, so the returned transaction uses Kit's standard unknown-height sentinel when the lifetime token changes. Broadcast promptly; local confirmation logic cannot detect blockhash expiry from an exact height in that case.

Mutation eligibility depends on whether signatures are supplied, not on `push_mode`. This SDK's native manual request is unsigned, omits `details.signatures`, and rejects pre-signed inputs, so Fordefi may refresh the blockhash and manage fees. A future provided-signatures flow must preserve the complete message byte-for-byte. `push_mode` controls submission only.

Durable-nonce transactions keep both their lifetime and fee layout exact. V1 transactions may replace only the blockhash and keep their inline transaction configuration exact.

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
| `pushMode` | No | `'auto'` (default) for Fordefi broadcasting or `'manual'` for caller broadcasting |
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

**`fordefi-signer.integration.test.ts`** exercises black box mode against the real Fordefi API and verifies the returned signatures with LiteSVM. It also exercises native manual signing when a Solana vault is configured; that test retrieves but does not broadcast the transaction.

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

Native manual vault:

```
FORDEFI_VAULT_ID=<solana-vault-uuid>
FORDEFI_PUBLIC_KEY=<solana-vault-address>
FORDEFI_CHAIN=solana_devnet
```

## License

MIT
