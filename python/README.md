# solana-keychain (Python)

Python implementation of `solana-keychain` — a unified `SolanaSigner` interface across
key-management backends, with parity to the [Rust crate](../rust/README.md) and the
[TypeScript packages](../typescript/README.md).

This is the foundation phase: the shared core contract plus the `memory` reference
backend. Remote backends are tracked as follow-ups.

## Supported backends

| Backend | Status |
| --- | --- |
| Memory | ✅ |
| Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Crossmint, CDP, Para, Openfort, Utila | Planned |

## Install

```bash
pip install solana-keychain
```

Requires Python ≥ 3.10. Built on [`solders`](https://pypi.org/project/solders/), whose
Rust-native `bincode` serialization keeps transaction bytes identical to the Rust crate
(verified by pinned golden vectors in `tests/test_parity.py`).

## Usage

```python
import asyncio

from solana_keychain import MemorySigner


async def main() -> None:
    signer = MemorySigner.from_private_key_file("/path/to/keypair.json")
    print(signer.pubkey)

    signature = await signer.sign_message(b"hello solana")

    # transaction: solders.transaction.Transaction
    result = await signer.sign_transaction(transaction)
    print(result.encoded_transaction)  # base64(bincode(tx))
    print(result.is_complete)  # False when co-signers still need to sign


asyncio.run(main())
```

`MemorySigner` also accepts a base58 string or a `"[1, 2, ..., 64]"` u8-array string via
`from_private_key_string`, raw 64-byte keys via `from_bytes`, and a `solders` `Keypair`
directly.

## Contract

Every backend implements `solana_keychain.SolanaSigner`:

- `pubkey` — the signer's public key (`solders.pubkey.Pubkey`)
- `async sign_transaction(tx)` — returns `SignedTransaction` (encoded tx, signature, completeness)
- `async sign_message(bytes)` — returns `solders.signature.Signature`
- `async is_available()` — health check

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
