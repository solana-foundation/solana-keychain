# @solana/keychain-fordefi

[Fordefi](https://docs.fordefi.com/) MPC signer for Solana transactions, part of the [@solana/keychain](https://github.com/solana-foundation/solana-keychain) family.

## Installation

```bash
npm install @solana/keychain-fordefi
```

## Signing Modes

The signer supports three modes, determined by `chain` and `pushMode`. Kit classifies signers by method presence, so each mode exposes exactly one transaction entry point and none of the others:

| Mode | Config | Shape | Entry point |
|------|--------|-------|-------------|
| Black box | `chain` unset | `FordefiBlackBoxSigner` | `signTransactions()` |
| Native auto | `chain` set, `pushMode` omitted or `'auto'` | `FordefiNativeSigner` | `signAndSendTransactions()` |
| Native manual | `chain` set, `pushMode: 'manual'` | `FordefiNativeManualSigner` | `modifyAndSignTransactions()` |

All three sign off-chain messages with `signMessages()`.

### Native auto mode (recommended for on-chain use)

Set `chain` to use Fordefi's native Solana transaction type. Fordefi may modify the transaction (e.g. updating the blockhash or adding compute budget instructions) and broadcasts it on-chain automatically. Use this with a **Solana vault**.

> **Note:** Native auto mode is a Kit `TransactionSendingSigner` (`FordefiNativeSigner`, built on `SolanaSendingSigner` from `@solana/keychain-core`), because Fordefi may sign a different message than the one supplied by the caller and broadcasts it itself. Use `signAndSendTransactionMessageWithSigners()` or `signAndSendTransactions()`. Instances expose **no** `signTransactions`: Kit classifies signers by method presence, so its absence is what routes the signer through Kit's sending flow. Message signing (`signMessages`) still works. Black-box instances are the mirror image: `signTransactions` and no `signAndSendTransactions`.

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

Add `pushMode: 'manual'` to the native config. Fordefi still parses the transaction, so its policy engine and approval UI apply, but it signs **without** broadcasting: you own submission, and additional required signers are supported, which native auto rejects.

Manual mode is a Kit `TransactionModifyingSigner` (`FordefiNativeManualSigner`, built on `SolanaModifyingSigner`). `modifyAndSignTransactions()` returns the transaction Fordefi signed, which **replaces** the one you submitted: continue from the returned value so every downstream signer signs the message the Fordefi signature covers.

```typescript
import { createFordefiSigner } from '@solana/keychain-fordefi';

const signer = await createFordefiSigner({
    accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
    vaultId: process.env.FORDEFI_VAULT_ID!,
    privateKeyPem: fs.readFileSync('./secret/private.pem', 'utf8'),
    publicKey: process.env.FORDEFI_PUBLIC_KEY!,
    chain: 'solana_devnet',
    pushMode: 'manual',
});

const [signedTransaction] = await signer.modifyAndSignTransactions([transaction]);
await rpc.sendTransaction(getBase64EncodedWireTransaction(signedTransaction), { encoding: 'base64' }).send();
```

Requirements and caveats:

- The Fordefi vault must be the transaction fee payer, and manual signing must run before any signature is applied. Both are checked before anything is submitted.
- Fordefi may rewrite the message: at minimum the recent blockhash, and it manages the Compute Budget fee instructions, so a compute-unit limit or price you set yourself may not survive. What changed is **not** diffed, so inspect the result before broadcasting if its contents matter to you.
- The returned signature is verified with ed25519 against the message Fordefi returned, at the vault's required-signer position. A mismatch fails and is never handed back.
- Fordefi refreshes the blockhash but does not report its `lastValidBlockHeight`, so a refreshed lifetime carries Kit's `U64_MAX` placeholder; broadcast promptly rather than relying on local expiry detection.
- The create carries an `x-idempotence-id` derived from the message bytes under a manual-specific namespace, so resending the same bytes reuses the Fordefi transaction instead of creating a second one, and cannot collide with an auto create that did broadcast them.

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
| `pushMode` | No | `'auto'` (default) or `'manual'`, i.e. whether Fordefi broadcasts. `'manual'` requires `chain` |
| `fee` | No | Priority fee config for native mode (e.g. `{ type: 'custom', priority_fee: '1000' }`) |
| `apiBaseUrl` | No | API base URL (default: `https://api.fordefi.com`) |
| `pollIntervalMs` | No | Polling interval in ms (default: 2000) |
| `maxPollAttempts` | No | Positive integer max polling attempts (default: 50) |
| `requestDelayMs` | No | Delay between requests in ms (default: 0). Native modes batch sequentially, so this is the gap between items |
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
