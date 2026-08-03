# solana-keychain (Python)

**Flexible, framework-agnostic Solana transaction signing for Python applications**

`solana-keychain` provides a unified interface for signing Solana transactions
with multiple backend implementations. Whether you need local keypairs for
development, enterprise vault integration, or managed wallet services, this
library offers a consistent API across all signing methods — with full parity to
the [Rust](../rust/README.md) and [TypeScript](../typescript/README.md) libraries.

## Features

- **Unified interface**: a single `SolanaSigner` contract for every backend
- **Async-first**: `sign_transaction` / `sign_message` / `is_available` are coroutines, matching the Rust and TS contracts
- **Cross-language parity**: the same signing contract and behavior as the Rust and TypeScript implementations, verified down to byte-identical transaction serialization
- **Safe errors**: `SignerError` redacts sensitive detail from its message; match on stable codes shared with the TypeScript `SignerErrorCode` values
- **Minimal core**: built on [`solders`](https://pypi.org/project/solders/) (Rust-native bindings), so `bincode` transaction bytes are identical to the Rust crate by construction

## Supported Backends

| Backend | Use Case | Module | Status |
| --- | --- | --- | --- |
| **Memory** | Local keypairs, development, testing | `solana_keychain.memory` | ✅ Available |
| **Vault** | Enterprise key management with HashiCorp Vault | — | Planned |
| **Privy** | Embedded wallets with Privy infrastructure | — | Planned |
| **Turnkey** | Non-custodial key management via Turnkey | — | Planned |
| **AWS KMS** | AWS Key Management Service with Ed25519 signing | — | Planned |
| **Fireblocks** | Fireblocks institutional custody platform | — | Planned |
| **GCP KMS** | Google Cloud Key Management Service with Ed25519 signing | — | Planned |
| **Dfns** | Dfns wallet infrastructure with Ed25519 signing | — | Planned |
| **Para** | MPC wallets with Para infrastructure | — | Planned |
| **CDP** | Coinbase Developer Platform managed wallets | — | Planned |
| **Crossmint** | Crossmint managed wallets | — | Planned |
| **Openfort** | Openfort backend wallets with TEE-stored keys | — | Planned |
| **Utila** | Utila MPC wallet integration | — | Planned |

## Installation

```bash
pip install solana-keychain
```

Requires **Python 3.10+**.

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

    # Sign a transaction (tx is a solders.transaction.Transaction):
    #   result = await signer.sign_transaction(tx)
    #   result.encoded_transaction  # base64 wire transaction
    #   result.signature            # this signer's signature
    #   result.is_complete          # are all required signatures present?


asyncio.run(main())
```

## Core API

Every signer implements the `SolanaSigner` ABC from `solana_keychain.core` — the
Python analog of the Rust `SolanaSigner` trait and the TypeScript `SolanaSigner`
interface:

```python
class SolanaSigner(ABC):
    @property
    def pubkey(self) -> Pubkey: ...

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction: ...

    async def sign_message(self, message: bytes) -> Signature: ...

    async def is_available(self) -> bool: ...
```

`sign_transaction` signs the transaction in place and returns a
`SignedTransaction(encoded_transaction, signature, is_complete)`; `is_complete`
reports whether every required signature is present (the Python analog of the
Rust `Complete`/`Partial` result).

Errors are always `SignerError` with a stable `code` shared with the TypeScript
`SignerErrorCode` values (`SIGNER_INVALID_PRIVATE_KEY`, `SIGNER_SIGNING_FAILED`, …).
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

Cross-language golden vectors are pinned in `tests/test_parity.py` — the same
canonical keypair, transaction, and `base64(bincode(tx))` bytes as the Rust
memory-signer tests.
