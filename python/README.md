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
        api_base_url="https://vault.example.com",
        token=os.environ["VAULT_TOKEN"],
        key_name="my-solana-key",
        public_key="4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR",
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
- With `chain` and `push_mode="manual"`, Fordefi may replace the recent
  blockhash and manage `SetComputeUnitPrice`/`SetComputeUnitLimit`, then signs
  the transaction without broadcasting it. Every other message field is
  validated exactly. Custom unit prices must match and custom priority fees cap
  the effective returned fee. The caller's solders transaction cannot have its
  read-only message replaced, so use `result.transaction` for downstream
  signing and broadcasting.

A priority fee Fordefi introduces on its own initiative is capped at
`DEFAULT_MAX_PRIORITY_FEE_LAMPORTS` (0.1 SOL), so a compromised or
malfunctioning response cannot drain the fee payer. Set
`max_priority_fee_lamports` to raise or lower that ceiling; a custom
`priority_fee` governs instead when set. The ceiling never applies to a
compute-unit price the caller placed in the transaction themselves, since those
requests are validated byte-for-byte.

The two fee instructions are asymmetric by design. A compute-unit *price*
you set yourself is protected: the whole message is then compared
byte-for-byte, so Fordefi can only replace the blockhash. A compute-unit
*limit* you set with no price is **not** preserved — Fordefi manages the limit
in manual mode, and the returned limit is only bounded indirectly, through the
lamport ceiling above. Set a compute-unit price alongside your limit if you
need the limit held exactly.

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

Mutation eligibility depends on whether signatures are supplied, not on
`push_mode`. This SDK's native manual request is unsigned, omits
`details.signatures`, and rejects pre-signed inputs, so Fordefi may refresh the
blockhash and manage fees. A future provided-signatures flow must preserve the
complete message byte-for-byte. `push_mode` controls submission only.
Durable-nonce transactions keep both their lifetime and fee layout exact; v1
transactions may replace only the blockhash and keep their inline configuration exact.

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

### Signer capabilities

Backends differ in whether the provider broadcasts the transaction and in whether
they can sign arbitrary bytes. `broadcasts_transactions` reports the first at
runtime; the second is fixed per backend:

| Backend | `broadcasts_transactions` | `sign_transaction` | `sign_and_send_transaction` | `sign_message` |
|---------|---------------------------|--------------------|-----------------------------|----------------|
| memory, vault, privy, turnkey, aws-kms, fireblocks, gcp-kms, dfns, para, openfort | False | yes | `SIGNING_FAILED` | yes |
| cdp | False | yes | `SIGNING_FAILED` | UTF-8 payloads only, otherwise `SERIALIZATION_ERROR` |
| crossmint | True | yes | yes | `SIGNING_FAILED` |
| utila | False | yes | `SIGNING_FAILED` | `SIGNING_FAILED` |
| fordefi (black-box mode) | False | yes | `SIGNING_FAILED` | yes |
| fordefi (native mode) | True | `SIGNING_FAILED` | yes | yes |

Crossmint supports both: it decides per request whether to rewrite and broadcast
the transaction or to sign the caller's exact bytes, and `sign_transaction`
exposes that distinction through an empty ``encoded_transaction``.

### Sign and Send

`sign_and_send_transaction` gets a transaction on chain with one call. Signers
whose `broadcasts_transactions` is True (Crossmint, Fordefi native mode) broadcast
through their provider and the send function is never called; every other signer
signs and the send function broadcasts the base64-encoded result:

```python
from solana_keychain import sign_and_send_transaction

signature = await sign_and_send_transaction(signer, transaction, rpc_send)
```

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
