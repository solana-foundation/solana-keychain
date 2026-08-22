# solana-keychain (Python)

**Flexible, framework-agnostic Solana transaction signing for Python applications**

`solana-keychain` provides a unified interface for signing Solana transactions
with multiple backend implementations. Whether you need local keypairs for
development, enterprise vault integration, or managed wallet services, this
library offers a consistent API across all signing methods.

## Features

- **Unified interface**: a single `SolanaSigner` contract for every backend
- **Async-first**: `sign_transaction` / `sign_message` / `is_available` are coroutines
- **Verified wire format**: golden-vector tests pin the exact serialized transaction bytes, so serialization can never silently drift
- **Safe errors**: `SignerError` redacts sensitive detail from its message; match on its stable `code` values
- **Minimal core**: built on [`solders`](https://pypi.org/project/solders/) for canonical transaction serialization and Ed25519 primitives

## Supported Backends

| Backend | Use Case | Module | Status |
| --- | --- | --- | --- |
| **Memory** | Local keypairs, development, testing | `solana_keychain.memory` | ✅ Available |
| **Vault** | Enterprise key management with HashiCorp Vault | `solana_keychain.vault` | ✅ Available |
| **Privy** | Embedded wallets with Privy infrastructure | `solana_keychain.privy` | ✅ Available |
| **Turnkey** | Non-custodial key management via Turnkey | `solana_keychain.turnkey` | ✅ Available |
| **AWS KMS** | AWS Key Management Service with Ed25519 signing | `solana_keychain.aws_kms` | ✅ Available |
| **Fireblocks** | Fireblocks institutional custody platform | `solana_keychain.fireblocks` | ✅ Available |
| **Fordefi** | Fordefi institutional MPC custody platform | `solana_keychain.fordefi` | ✅ Available |
| **GCP KMS** | Google Cloud Key Management Service with Ed25519 signing | `solana_keychain.gcp_kms` | ✅ Available |
| **Dfns** | Dfns wallet infrastructure with Ed25519 signing | `solana_keychain.dfns` | ✅ Available |
| **Para** | MPC wallets with Para infrastructure | `solana_keychain.para` | ✅ Available |
| **CDP** | Coinbase Developer Platform managed wallets | `solana_keychain.cdp` | ✅ Available |
| **Crossmint** | Crossmint managed wallets | `solana_keychain.crossmint` | ✅ Available |
| **Openfort** | Openfort backend wallets with TEE-stored keys | `solana_keychain.openfort` | ✅ Available |
| **Utila** | Utila MPC wallet integration | `solana_keychain.utila` | ✅ Available |

## Installation

```bash
pip install solana-keychain              # memory + vault
pip install 'solana-keychain[aws-kms]'   # adds the AWS KMS backend
pip install 'solana-keychain[cdp]'       # adds the CDP backend
pip install 'solana-keychain[crossmint]' # adds the Crossmint backend
pip install 'solana-keychain[dfns]'      # adds the Dfns backend
pip install 'solana-keychain[fireblocks]' # adds the Fireblocks backend
pip install 'solana-keychain[fordefi]'   # adds the Fordefi backend
pip install 'solana-keychain[gcp-kms]'   # adds the GCP KMS backend
pip install 'solana-keychain[openfort]'  # adds the Openfort backend
pip install 'solana-keychain[privy]'     # adds the Privy backend
pip install 'solana-keychain[turnkey]'   # adds the Turnkey backend
pip install 'solana-keychain[utila]'     # adds the Utila backend
```

Requires **Python 3.10+**. Backends built on heavy provider SDKs ship as optional
extras; importing such a backend without its extra raises an `ImportError` naming
the extra to install. Extras-gated backends are imported from their submodule
(e.g. `from solana_keychain.aws_kms import create_aws_kms_signer`), not from the
package root.

## Quick Start

### Memory Signer (Local Development)

```python
import asyncio

from solana_keychain import MemorySigner


async def main() -> None:
    # Build a signer from a base58 key, a "[1,2,...]" byte array, raw bytes,
    # or a Solana CLI keypair file.
    signer = MemorySigner.from_private_key_file("/path/to/keypair.json")
    print("address:", signer.pubkey)

    # Sign an arbitrary message.
    signature = await signer.sign_message(b"Hello Solana!")
    print("signature:", signature)

    # Sign a transaction (tx is a solders.transaction.VersionedTransaction):
    #   result = await signer.sign_transaction(tx)
    #   result.encoded_transaction  # base64 wire transaction
    #   result.signature            # this signer's signature
    #   result.is_complete          # are all required signatures present?
    #   result.transaction          # authoritative provider replacement, when present


asyncio.run(main())
```

### Remote Backends

Every remote backend follows the same pattern: a config dataclass and an async
`create_<backend>_signer` factory that returns a ready-to-use signer:

```python
from solana_keychain import VaultSignerConfig, create_vault_signer

signer = await create_vault_signer(
    VaultSignerConfig(
        vault_addr="https://vault.example.com",
        token=os.environ["VAULT_TOKEN"],
        key_name="my-solana-key",
        pubkey="4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR",
    )
)
```

Remote HTTP backends accept an optional `http_client` override in their config
(an `httpx.AsyncClient`, for custom TLS or proxies); when unset, requests go
through an HTTPS-enforcing one-shot client with a 60s timeout and redirects
rejected.

### Fordefi signing modes

Fordefi supports three transaction modes:

- With no `chain`, black-box mode signs the caller's exact message bytes and
  leaves broadcasting to the caller.
- With `chain` and the default `push_mode="auto"`, Fordefi may update the
  blockhash and fees, then signs and broadcasts the transaction. The result's
  encoded transaction is empty and the caller's transaction remains untouched.
- With `chain` and `push_mode="manual"`, Fordefi may modify and sign the
  transaction but does not broadcast it. The caller's solders transaction
  cannot have its read-only message replaced, so use `result.transaction` as
  the authoritative transaction for downstream signing and broadcasting.

```python
import os

from solana_keychain.fordefi import FordefiSignerConfig, create_fordefi_signer

signer = await create_fordefi_signer(
    FordefiSignerConfig(
        access_token=os.environ["FORDEFI_ACCESS_TOKEN"],
        vault_id=os.environ["FORDEFI_VAULT_ID"],
        public_key=os.environ["FORDEFI_PUBLIC_KEY"],
        private_key_pem=os.environ["FORDEFI_PRIVATE_KEY_PEM"],
        chain="solana_mainnet",
        push_mode="manual",
    )
)

result = await signer.sign_transaction(transaction)
fordefi_transaction = result.transaction
if fordefi_transaction is None:
    raise RuntimeError("Fordefi manual signing did not return a transaction")

if result.is_complete:
    # Broadcast result.encoded_transaction through your RPC client.
    pass
else:
    # Apply downstream signatures to fordefi_transaction, reserialize, and broadcast.
    pass
```

Manual mode requires Fordefi to be the fee payer and to sign before every
downstream signer. Fordefi normally refreshes the transaction blockhash but
does not return its exact `lastValidBlockHeight`; broadcast manual results
promptly rather than relying on a locally known block-height expiry.

## Core API

Every signer implements the `SolanaSigner` ABC from `solana_keychain.core`:

```python
class SolanaSigner(ABC):
    @property
    def pubkey(self) -> Pubkey: ...

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction: ...

    async def sign_message(self, message: bytes) -> Signature: ...

    async def is_available(self) -> bool: ...
```

`sign_transaction` returns a
`SignedTransaction(encoded_transaction, signature, is_complete, transaction=...)`;
`is_complete` reports whether every required signature is present. Most signers
modify the supplied transaction in place. When a provider returns authoritative
replacement bytes that cannot be applied in place, the optional `transaction`
field carries the replacement. Legacy, v0 and v1 transactions are accepted.

Errors are always `SignerError` with a stable `code`
(`SIGNER_INVALID_PRIVATE_KEY`, `SIGNER_SIGNING_FAILED`, …).
`str()`/`repr()` of a `SignerError` never include key material or raw remote responses.

## Development

From the repo root (recipes bootstrap `python/.venv` automatically):

```bash
just py-test    # unit tests
just py-fmt     # ruff format + lint + mypy
just py-build   # sdist + wheel
```

Or manually:

```bash
cd python
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

Golden wire-format vectors are pinned in `tests/test_parity.py` — the exact
serialized bytes for one canonical transaction. Never regenerate them to make
the suite pass; a mismatch means the library's output has drifted from the
Solana wire format.
