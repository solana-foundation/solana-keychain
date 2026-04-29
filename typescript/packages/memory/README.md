# @solana/keychain-memory

In-memory Ed25519 keypair signer for Solana transactions.

The private key never leaves the local process — all signing happens via the Web Crypto API. Useful for development, integration tests, and server-side signing where a remote vendor is overkill.

## Installation

```bash
pnpm add @solana/keychain-memory
```

## Usage

### From a Solana CLI keypair file

```typescript
import { createMemorySignerFromKeypairFile } from '@solana/keychain-memory';

const signer = await createMemorySignerFromKeypairFile('/path/to/id.json');
console.log('Signer address:', signer.address);
```

### From a base58 private key string

```typescript
import { createMemorySignerFromPrivateKeyString } from '@solana/keychain-memory';

const signer = await createMemorySignerFromPrivateKeyString(process.env.SOLANA_PRIVATE_KEY!);
```

### From a U8Array string (Solana CLI inline format)

```typescript
import { createMemorySignerFromPrivateKeyString } from '@solana/keychain-memory';

const signer = await createMemorySignerFromPrivateKeyString('[1, 2, 3, ..., 64]');
```

### From raw bytes

Accepts either a 64-byte Solana CLI keypair (seed concatenated with public key — seed↔pubkey match is validated) or a 32-byte Ed25519 seed (public key derived).

```typescript
import { createMemorySignerFromBytes } from '@solana/keychain-memory';

// 64 bytes: Solana CLI format
const signer = await createMemorySignerFromBytes(solanaCliKeypairBytes);

// 32 bytes: raw Ed25519 seed (e.g. exported from generateKey)
const signerFromSeed = await createMemorySignerFromBytes(seed32);
```

### From an existing CryptoKeyPair

```typescript
import { generateKeyPair } from '@solana/keys';
import { createMemorySignerFromKeyPair } from '@solana/keychain-memory';

const keyPair = await generateKeyPair();
const signer = await createMemorySignerFromKeyPair(keyPair);
```

### Unified factory

```typescript
import { createMemorySigner } from '@solana/keychain-memory';

const signer = await createMemorySigner({
    privateKeyString: process.env.SOLANA_PRIVATE_KEY!,
});
```

Provide exactly one of: `keyPair`, `privateKey`, `privateKeyString`, `privateKeyPath`.

### Sign messages and transactions

```typescript
import { createSignableMessage } from '@solana/signers';

const message = createSignableMessage('Hello, Solana!');
const [messageSignatures] = await signer.signMessages([message]);

const [transactionSignatures] = await signer.signTransactions([transaction]);
```

### Check availability

```typescript
const available = await signer.isAvailable(); // always true
```

## API Reference

### `createMemorySigner(config)`

Returns `Promise<SolanaSigner>`.

Config (`MemorySignerConfig`):
- `keyPair?: CryptoKeyPair` — pre-built CryptoKeyPair (e.g. from `generateKeyPair`)
- `privateKey?: Uint8Array` — 64-byte Solana keypair (seed‖pubkey, validated) OR 32-byte Ed25519 seed (pubkey derived)
- `privateKeyString?: string` — base58 OR U8Array string `"[1, 2, ..., 64]"`
- `privateKeyPath?: string` — path to a Solana CLI keypair JSON file (Node-only)

### Named factories

- `createMemorySignerFromKeyPair(keyPair)`
- `createMemorySignerFromBytes(privateKey)`
- `createMemorySignerFromPrivateKeyString(privateKeyString)` — auto-detects base58 vs U8Array
- `createMemorySignerFromKeypairFile(privateKeyPath)` — Node-only

## Security Notes

- The private key is held in memory as a non-extractable `CryptoKey` — it cannot be exported back to bytes.
- Do not hardcode private keys in source files. Use environment variables, secret managers, or operator-supplied keypair files.
- For production wallets, prefer a remote signer backend (AWS KMS, GCP KMS, Turnkey, Privy, etc.).
