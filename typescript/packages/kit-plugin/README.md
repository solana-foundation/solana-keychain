# @solana/keychain-kit-plugin

[Kit client](https://github.com/anza-xyz/kit) plugins that create a keychain signer from any supported backend and install it on the client as the `payer` and/or `identity`.

## Installation

```sh
pnpm add @solana/keychain-kit-plugin @solana/kit
```

## Usage

Each plugin accepts the same backend-tagged configuration as [`createKeychainSigner`](../keychain/README.md) from `@solana/keychain`:

```ts
import { createClient } from '@solana/kit';
import { keychainSigner } from '@solana/keychain-kit-plugin';

const client = await createClient().use(
    keychainSigner({
        backend: 'privy',
        appId: process.env.PRIVY_APP_ID!,
        appSecret: process.env.PRIVY_APP_SECRET!,
        walletId: process.env.PRIVY_WALLET_ID!,
    }),
);

client.payer; // SolanaTransactionSigner — also a Kit TransactionPartialSigner
client.identity; // same signer instance
```

Only the backend a configuration dispatches to is bundled — backend packages are loaded with dynamic `import()`.

## Managed-broadcast backends are excluded

Crossmint, and Fordefi in native mode (`chain` set), rewrite and broadcast transactions server-side. They are Kit `TransactionSendingSigner`s with no `signTransactions`, so they cannot serve as a client `payer` or `identity` — client send flows build, sign, and broadcast themselves, and Kit routes a sending signer only through `signAndSendTransactionMessageWithSigners()`. These plugins reject such configs at compile time (`KeychainKitPluginConfig`). Use the signer directly instead:

```ts
import { signAndSendTransactionMessageWithSigners } from '@solana/signers';
import { createKeychainSigner } from '@solana/keychain';

const crossmint = await createKeychainSigner({ backend: 'crossmint', apiKey, walletLocator });
const signature = await signAndSendTransactionMessageWithSigners(transactionMessage);
```

Fordefi in black-box mode (no `chain`) is a regular partial signer and remains supported.

## Plugin variants

| Plugin                    | Sets                                          |
| ------------------------- | --------------------------------------------- |
| `keychainSigner(config)`  | Both `payer` **and** `identity` (same signer) |
| `keychainPayer(config)`   | Only `payer`                                  |
| `keychainIdentity(config)` | Only `identity`                               |

Mix backends on one client:

```ts
import { createClient } from '@solana/kit';
import { keychainIdentity, keychainPayer } from '@solana/keychain-kit-plugin';

const client = await createClient()
    .use(keychainPayer({ backend: 'memory', privateKeyPath: '~/.config/solana/id.json' }))
    .use(keychainIdentity({ backend: 'turnkey', ...turnkeyConfig }));
```

## Already have a signer?

If you've already constructed a `SolanaTransactionSigner` (or want to share one across clients), you don't need this package — every such signer is a valid Kit `TransactionPartialSigner`, so [`@solana/kit-plugin-signer`](https://github.com/anza-xyz/kit-plugins/tree/main/packages/kit-plugin-signer) works directly:

```ts
import { signer } from '@solana/kit-plugin-signer';
import { createKeychainSigner } from '@solana/keychain';

const mySigner = await createKeychainSigner({ backend: 'vault', ...vaultConfig });
const client = createClient().use(signer(mySigner));
```
