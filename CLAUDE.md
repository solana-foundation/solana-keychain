# CLAUDE.md

Guidance for Claude Code working in this repo.

## Project Overview

`solana-keychain` is a Rust + TypeScript + Python + Go library providing a unified `SolanaSigner` interface across thirteen backends, with full cross-language parity:

Memory · Vault · Privy · Turnkey · AWS KMS · Fireblocks · GCP KMS · Dfns · Crossmint · CDP · Para · Openfort · Utila

## Repo Layout

- `rust/` — Rust crate, feature-gated per backend. See [rust/README.md](rust/README.md).
- `typescript/` — pnpm monorepo, one package per backend plus core/keychain umbrella. See [typescript/README.md](typescript/README.md).
- `python/` — Python package (`solana-keychain`). See [python/README.md](python/README.md).
- `docs/ADDING_SIGNERS.md` — full guide for adding a new backend (Rust + TS + CI).
- `audits/AUDIT_STATUS.md` — audited-through commit and unaudited delta.
- `justfile` — top-level dev commands. Prefer these over raw `cargo`/`pnpm` since they encode the right flags (e.g., `just rust-test` runs the `sdk-v2`, `sdk-v3`, and `sdk-v4` matrices — `cargo test --all-features` fails because the SDK features are mutually exclusive).

### Common commands

Always prefer `just` recipes. They encode the right flags (e.g., `just rust-test` runs the `sdk-v2`, `sdk-v3`, and `sdk-v4` matrices — `cargo test --all-features` fails because the SDK features are mutually exclusive). Run `just` with no args to list every recipe.

```bash
just build              # rust-build + ts-build
just test               # unit tests (rust + ts)
just test-integration   # spins up local Vault, runs integration tests (both sides)
just test-all           # test + test-integration
just fmt                # cargo fmt/clippy + pnpm lint:fix/format
```

Per-side recipes (use these to scope work to one language):

| Task | Rust | TypeScript | Python |
| --- | --- | --- | --- |
| Build | `just rust-build` | `just ts-build` | `just py-build` |
| Unit tests | `just rust-test` | `just ts-test` | `just py-test` |
| Format + lint | `just rust-fmt` | `just ts-fmt` | `just py-fmt` |
| Integration tests | `just rust-test-integration` | `just ts-test-integration` | `just py-test-integration` |
| Other | — | `just ts-treeshake` (verifies `@solana/keychain` umbrella + per-pkg tree-shakability) | — |

Integration recipes auto-spawn a local `vault server -dev` and load `.env` from the repo root — do not run vault yourself or pass secrets via shell.

For releases: `just release` (Rust), `just release-ts`, `just hotfix`, `just publish-ts`. See [RELEASING.md](RELEASING.md) for the full runbook (normal flow, partial-publish recovery, new-package onboarding, concurrency notes). Always check **all** crates/packages in the monorepo for version consistency.

## Repo skills

This repo ships Claude Code skills in [.claude/skills/](.claude/skills/) — invoke them whenever you're starting one of these workflows instead of reinventing the steps:

| Skill | When to use |
| --- | --- |
| [`add-signer`](.claude/skills/add-signer/SKILL.md) | Adding a new signing backend (Rust + TS + CI). Pair with [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md). |
| [`release`](.claude/skills/release/SKILL.md) | Cutting a new Rust and/or TS release (PR-based flow, version bumps). |
| [`complete-release`](.claude/skills/complete-release/SKILL.md) | Finalizing an approved release PR — merge, then trigger publish workflows from `main`. |

## Rust

Use `just rust-*` for the common workflows. For a single-backend slice (no `just` recipe), drop to cargo:

```bash
cd rust && cargo test --no-default-features --features <backend>,sdk-v2 <backend>::tests
```

Remember to also run `sdk-v3` and `sdk-v4` if your change touches SDK-version-sensitive code — `just rust-test` does all three for you.

### Architecture

- **Trait** ([rust/src/traits.rs](rust/src/traits.rs)): `SolanaSigner` with `pubkey()`, `sign_transaction()`, `sign_message()`, `is_available()`.
- **Unified enum** ([rust/src/lib.rs](rust/src/lib.rs)): `Signer` enum wraps every backend, each variant `#[cfg(feature = "...")]`-gated. `Signer::from_<backend>(...)` constructors return a ready-to-use signer (calling `init()` internally where needed).
- **Errors** ([rust/src/error.rs](rust/src/error.rs)): centralized `SignerError` via `thiserror`.

Per-backend implementation details live in each module's source. See [rust/README.md](rust/README.md) for the supported-backend table and usage examples.

### Feature flags

One feature per backend (`memory` is default), `all` enables everything. At least one is required (enforced by `compile_error!` in `lib.rs`). SDK selection is mutually exclusive: `sdk-v2` (default), `sdk-v3`, or `sdk-v4` (solana-sdk 4.x).

### Gotchas

- **`init()` required before use:** `PrivySigner`, `FireblocksSigner`, `DfnsSigner`, `CrossmintSigner`, `ParaSigner`, `OpenfortSigner`. The others are ready after construction. The `Signer::from_*` factories handle `init()` for you.
- **`sign_message` quirks:** `CrossmintSigner` returns `SigningFailed` (intentionally unsupported). `CdpSigner` only accepts UTF-8 payloads.
- **Turnkey signature padding:** response `r,s` components must be left-padded to 32 bytes each before concatenation ([rust/src/turnkey/mod.rs](rust/src/turnkey/mod.rs)).
- **GCP KMS:** PureEdDSA mode with `EC_SIGN_ED25519`.
- **Transaction serialization:** go through `transaction_util::serialize_wire_transaction` / `deserialize_wire_transaction`, never `bincode` directly (`sdk-v4` needs `wincode` for v1).
- **Transaction types:** `sign_transaction` takes a `VersionedTransaction` (legacy, v0 or v1). v1 messages exist only in the solana-sdk 4.x line, so v1 requires `sdk-v4` and is unrepresentable under `sdk-v2`/`sdk-v3`.
- **Remote-signer tests** use `wiremock`; no live API calls in unit tests.

## TypeScript

Use `just ts-*` for build/test/fmt/treeshake. For a single-package slice (no `just` recipe), drop to pnpm:

```bash
cd typescript && pnpm install
cd typescript && pnpm --filter @solana/keychain-<name> <script>   # e.g. test, build, typecheck
cd typescript && pnpm typecheck                                    # workspace-wide
```

### Architecture

- **Monorepo** ([typescript/](typescript/)): pnpm workspace, one package per backend plus `core` (interfaces) and `keychain` (umbrella factory).
- **Interface** (`@solana/keychain-core`): every signer implements `SolanaSigner<TAddress>` — `address`, `signMessages()`, `signTransactions()`, `isAvailable()`. Compatible with `@solana/kit` and `@solana/signers`.
- **Async factory pattern:** each package exports `async createXSigner(config)` returning a ready-to-use `SolanaSigner` (the factory awaits any `init()` internally — TS parity with Rust's `Signer::from_*`). The umbrella `@solana/keychain` exports `createKeychainSigner({ backend, ...config })` that dispatches to the per-backend factory.
- **Package naming:** `@solana/keychain-<backend>` (e.g. `@solana/keychain-privy`, `@solana/keychain-aws-kms`).

See [typescript/README.md](typescript/README.md) for the full package list and usage. When adding a backend, follow [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md) — the umbrella package needs updates in 7 places (including the treeshake script).

### Gotchas

- **Async construction:** always `await createXSigner(...)` — direct class construction is deprecated and skips `init()`.
- **Managed-broadcast backends (Crossmint, Fordefi native mode):** implement `SolanaSendingSigner` from core — `signAndSendTransactions()` only, with **no** `signTransactions`/`signMessages` (Crossmint) because Kit classifies signers by duck-typed method presence. They are excluded from `@solana/keychain-kit-plugin` at the type level.
- **`signMessages` quirks (parity with Rust):** `CrossmintSigner` does not expose `signMessages` at all (Rust returns `SigningFailed`). `CdpSigner` requires UTF-8 message bytes.
- **HTTPS enforced:** all `apiBaseUrl` config fields must reject non-HTTPS URLs — validate with `assertHttpsUrl()` from `@solana/keychain-core`.
- **Remote API calls:** go through `fetchSignerJson()` from `@solana/keychain-core` — it owns the HTTP_ERROR/REMOTE_API_ERROR/PARSING_ERROR pipeline, response sanitization (`sanitizeRemoteErrorResponse()`), redirect rejection, and a default 60s timeout. Batch signing uses core `signBatchStaggered()` + `validateRequestDelayMs()`.
- **Integration tests:** use `runSignerIntegrationTest` + per-package `setup.ts`; spun up via `just ts-test-integration` (loads `.env`, starts local Vault).
- **Tree-shakability:** run `just ts-treeshake` after touching exports — every package and the umbrella must stay tree-shakable.
- **Adding a backend:** the umbrella package, `typescript-ci.yml`, and `typescript-publish.yml` all need updates (see [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md)).

## Python

Single package under [python/](python/) (PyPI `solana-keychain`, import `solana_keychain`), src layout, hatchling. The `just py-*` recipes bootstrap `python/.venv` automatically (plain venv + pip; `rm -rf python/.venv` to refresh after dependency changes). Tooling: pytest (+pytest-asyncio, auto mode), ruff (format + lint), mypy strict.

### Architecture

- **Contract** (`solana_keychain.core`): `SolanaSigner` ABC — `pubkey` property, async `sign_transaction()` / `sign_message()` / `is_available()`. `sign_transaction` takes a `VersionedTransaction` (legacy, v0 or v1) and returns `SignedTransaction` with `is_complete`. Use `signed_message_bytes()` for the bytes a signature covers; never hand-roll the version prefix.
- **Errors**: `SignerError` with stable `code` values; `str()`/`repr()` only surface generic messages (detail is redacted and must never leak key material or raw remote responses).
- **Serialization**: built on `solders`; golden wire-format vectors pinned in `python/tests/test_parity.py` — never regenerate them to make the suite pass.
- **Remote API calls** go through `fetch_signer_json()` from `solana_keychain.core` — it owns the HTTP_ERROR/REMOTE_API_ERROR/PARSING_ERROR pipeline, response sanitization, redirect rejection, and a default 60s timeout. Base URLs must pass `assert_https_url()`. Unit tests mock HTTP with `respx`; no live API calls in unit tests.
- **Backend imports/extras rules**: the root `__init__.py` must never eagerly import a backend whose dependencies live behind an optional extra (use lazy `__getattr__` or leave it to submodule imports), and such backends must raise a clear "install `solana-keychain[<extra>]`" error when imported without their extra. Backends with only base deps (`solders`, `httpx`) may be exported eagerly.
- **Umbrella factory**: `create_keychain_signer(backend, config)` in `solana_keychain/keychain.py` dispatches by backend name with lazy imports; new backends must be added to its `_BACKENDS` table.
- **Integration tests**: `python/tests/integration/`, gated by the `integration` pytest marker (excluded by default via `addopts`), env-var-driven with the same variable names as the other integration suites; each backend skips itself when unconfigured. `just py-test-integration` runs the local Vault flow.

## Branch Workflow

- `main` — integration branch (audited + unaudited).
- `feat/*`, `fix/*`, `chore/*` — topic branches from `main`.
- `hotfix/*` — urgent fixes from a deployed stable tag (use `just hotfix`).

`just branch-info` prints the full guidance.
