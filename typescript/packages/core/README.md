# @solana/keychain-core

Core interfaces and utilities for building external Solana signers.

## Installation

```bash
pnpm add @solana/keychain-core
```

## What's Included

### Interfaces

One capability interface per Kit signer shape, each adding `isAvailable(): Promise<boolean>` to the corresponding `@solana/signers` interface. Signing methods inherit Kit's optional config — including `{ abortSignal }` to cancel an in-flight signing request.

**`SolanaTransactionSigner`** - A signer that returns signatures for a caller-owned transaction. Extends Kit's `TransactionPartialSigner`:

```typescript
import { SolanaTransactionSigner } from '@solana/keychain-core';

interface SolanaTransactionSigner {
    address: Address;
    isAvailable(): Promise<boolean>;
    signTransactions(
        transactions: readonly Transaction[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]>;
}
```

**`SolanaModifyingSigner`** - A signer that may rewrite parts of the transaction before signing it, then returns the modified transaction without broadcasting. Extends Kit's `TransactionModifyingSigner`. No keychain backend has this shape yet.

**`SolanaSendingSigner`** - Interface for managed-broadcast backends. A backend belongs in this category when it rewrites the transaction message and/or broadcasts server-side, so its signature cannot be applied to the caller's transaction. Such signers expose `signAndSendTransactions()` (Kit's `TransactionSendingSigner`) and deliberately **no** `signTransactions` — Kit classifies signers by duck-typed method presence, and a present-but-throwing method would make Kit misroute the transaction and fail at runtime:

```typescript
import { SolanaSendingSigner } from '@solana/keychain-core';

interface SolanaSendingSigner {
    address: Address;
    isAvailable(): Promise<boolean>;
    signAndSendTransactions(transactions: readonly Transaction[]): Promise<readonly SignatureBytes[]>;
}
```

**`SolanaMessageSigner`** - A signer that signs off-chain messages via `signMessages()`. Extends Kit's `MessagePartialSigner`. Message signing is orthogonal to the transaction shapes, exactly as Kit separates `MessageSigner` from `TransactionSigner`: a backend that signs messages intersects this interface with its transaction shape (`SolanaTransactionSigner & SolanaMessageSigner` for most backends), and a backend that does not (Crossmint, Utila) exposes no `signMessages` method at all.

**`SolanaSigner`** - Any keychain signer: the union `SolanaModifyingSigner | SolanaSendingSigner | SolanaTransactionSigner`, mirroring Kit's `TransactionSigner` union. Which shape a signer has is not knowable from this type, so narrow with the guards below before calling a signing method.

Runtime guards: `isSolanaSigner()`, `isSolanaTransactionSigner()`, `isSolanaModifyingSigner()`, `isSolanaSendingSigner()`, `isSolanaMessageSigner()`, `assertIsSolanaSigner()`, and `assertIsSolanaTransactionSigner()`. `signerCapabilities(signer)` reports the same information as a `{ canModifyTransactions, canSignAndSend, canSignMessages, canSignTransactions }` record.

### Error Handling

```typescript
import { SignerError, SignerErrorCode, throwSignerError } from '@solana/keychain-core';

// Check error type
if (error instanceof SignerError) {
    console.log(error.code); // e.g., 'SIGNER_SIGNING_FAILED'
    console.log(error.context); // Additional error details
}

// Throw typed errors
throwSignerError(SignerErrorCode.SIGNING_FAILED, {
    address: 'signer-address',
    message: 'Custom error message'
});
```

**Available error codes:**
- `INVALID_PRIVATE_KEY` - Invalid private key format
- `INVALID_PUBLIC_KEY` - Invalid public key format
- `SIGNING_FAILED` - Signing operation failed
- `REMOTE_API_ERROR` - Remote signer API error
- `HTTP_ERROR` - HTTP request failed
- `SERIALIZATION_ERROR` - Transaction serialization failed
- `CONFIG_ERROR` - Invalid configuration
- `NOT_AVAILABLE` - Signer not available/healthy
- `IO_ERROR` - File I/O error
- `PRIVY_NOT_INITIALIZED` - Privy signer not initialized

### Utilities

**`extractSignatureFromWireTransaction`** - Extract a specific signer's signature from a signed transaction:

```typescript
import { extractSignatureFromWireTransaction } from '@solana/keychain-core';

// When a remote API returns a fully signed base64 transaction, we need to extract the signature to use Kit's native methods (which rely on .signTransactions to return a SignatureDictionary)
const signedTx = await remoteApi.signTransaction(...);
const sigDict = extractSignatureFromWireTransaction({
    base64WireTransaction: signedTx,
    signerAddress: myAddress
});
```

**`createSignatureDictionary`** - Create a signature dictionary from raw signature bytes:

```typescript
import { createSignatureDictionary } from '@solana/keychain-core';

const sigDict = createSignatureDictionary({
    signature: signatureBytes,
    signerAddress: myAddress
});
```

## Usage

This package is typically used as a dependency when building custom signer implementations. See [@solana/keychain-privy](https://www.npmjs.com/package/@solana/keychain-privy) for an example implementation.

```typescript
import { SolanaMessageSigner, SolanaTransactionSigner, SignerErrorCode, throwSignerError } from '@solana/keychain-core';

class MyCustomSigner implements SolanaTransactionSigner, SolanaMessageSigner {
    readonly address: Address;

    async isAvailable(): Promise<boolean> {
        // Check if backend is healthy
    }

    async signMessages(messages: readonly SignableMessage[], config?: MessagePartialSignerConfig) {
        // Sign messages using your backend, honoring config?.abortSignal
    }

    async signTransactions(transactions: readonly Transaction[], config?: TransactionPartialSignerConfig) {
        // Sign transactions using your backend, honoring config?.abortSignal
    }
}
```

## Type Guards

**`isSolanaSigner`** - Check if a value is a `SolanaSigner` (any of the three transaction shapes):

```typescript
import { isSolanaSigner } from '@solana/keychain-core';

const isSigner = isSolanaSigner(value); // true or false
```

**`isSolanaTransactionSigner`** / **`isSolanaModifyingSigner`** / **`isSolanaSendingSigner`** - Narrow a `SolanaSigner` to its transaction shape before calling a signing method:

```typescript
import { isSolanaSendingSigner, isSolanaTransactionSigner } from '@solana/keychain-core';

if (isSolanaSendingSigner(signer)) {
    await signer.signAndSendTransactions([transaction]);
} else if (isSolanaTransactionSigner(signer)) {
    await signer.signTransactions([transaction]);
}
```

**`isSolanaMessageSigner`** - Check whether a signer signs off-chain messages via `signMessages`.

**`assertIsSolanaSigner`** - Assert that a value is a SolanaSigner:

```typescript
import { assertIsSolanaSigner } from '@solana/keychain-core';

assertIsSolanaSigner(value); // void (throws if not a SolanaSigner)
```

**`assertIsSolanaTransactionSigner`** - Assert that a value is a SolanaTransactionSigner. Use this where a signer must return signatures for a caller-owned transaction, e.g. before installing it as a Kit client `payer`/`identity`; a managed-broadcast signer fails this assertion.