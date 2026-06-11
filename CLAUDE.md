# CLAUDE.md

Guidance for Claude Code working in this repo.

## Project Overview

`solana-keychain` is a Rust + TypeScript library providing a unified `SolanaSigner` interface across twelve backends, with full Rust/TS parity:

Memory · Vault · Privy · Turnkey · AWS KMS · Fireblocks · GCP KMS · Dfns · Crossmint · CDP · Para · Openfort

## Repo Layout

- `rust/` — Rust crate, feature-gated per backend. See [rust/README.md](rust/README.md).
- `typescript/` — pnpm monorepo, one package per backend plus core/keychain umbrella. See [typescript/README.md](typescript/README.md).
- `docs/ADDING_SIGNERS.md` — full guide for adding a new backend (Rust + TS + CI).
- `audits/AUDIT_STATUS.md` — audited-through commit and unaudited delta.
- `justfile` — top-level dev commands. Prefer these over raw `cargo`/`pnpm` since they encode the right flags (e.g., `just rust-test` runs both `sdk-v2` and `sdk-v3` matrices — `cargo test --all-features` fails because the SDK features are mutually exclusive).

### Common commands

Always prefer `just` recipes. They encode the right flags (e.g., `just rust-test` runs both `sdk-v2` and `sdk-v3` matrices — `cargo test --all-features` fails because the SDK features are mutually exclusive). Run `just` with no args to list every recipe.

```bash
just build              # rust-build + ts-build
just test               # unit tests (rust + ts)
just test-integration   # spins up local Vault, runs integration tests (both sides)
just test-all           # test + test-integration
just fmt                # cargo fmt/clippy + pnpm lint:fix/format
```

Per-side recipes (use these to scope work to one language):

| Task | Rust | TypeScript |
| --- | --- | --- |
| Build | `just rust-build` | `just ts-build` |
| Unit tests | `just rust-test` | `just ts-test` |
| Format + lint | `just rust-fmt` | `just ts-fmt` |
| Integration tests | `just rust-test-integration` | `just ts-test-integration` |
| Other | — | `just ts-treeshake` (verifies `@solana/keychain` umbrella + per-pkg tree-shakability) |

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

Remember to also run `sdk-v3` if your change touches SDK-version-sensitive code — `just rust-test` does both for you.

### Architecture

- **Trait** ([rust/src/traits.rs](rust/src/traits.rs)): `SolanaSigner` with `pubkey()`, `sign_transaction()`, `sign_message()`, `is_available()`.
- **Unified enum** ([rust/src/lib.rs](rust/src/lib.rs)): `Signer` enum wraps every backend, each variant `#[cfg(feature = "...")]`-gated. `Signer::from_<backend>(...)` constructors return a ready-to-use signer (calling `init()` internally where needed).
- **Errors** ([rust/src/error.rs](rust/src/error.rs)): centralized `SignerError` via `thiserror`.

Per-backend implementation details live in each module's source. See [rust/README.md](rust/README.md) for the supported-backend table and usage examples.

### Feature flags

One feature per backend (`memory` is default), `all` enables everything. At least one is required (enforced by `compile_error!` in `lib.rs`). SDK selection is mutually exclusive: `sdk-v2` (default) or `sdk-v3`.

### Gotchas

- **`init()` required before use:** `PrivySigner`, `FireblocksSigner`, `DfnsSigner`, `CrossmintSigner`, `ParaSigner`, `OpenfortSigner`. The others are ready after construction. The `Signer::from_*` factories handle `init()` for you.
- **`sign_message` quirks:** `CrossmintSigner` returns `SigningFailed` (intentionally unsupported). `CdpSigner` only accepts UTF-8 payloads.
- **Turnkey signature padding:** response `r,s` components must be left-padded to 32 bytes each before concatenation ([rust/src/turnkey/mod.rs](rust/src/turnkey/mod.rs)).
- **GCP KMS:** PureEdDSA mode with `EC_SIGN_ED25519`.
- **Transaction serialization:** all backends use `bincode` before signing.
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

See [typescript/README.md](typescript/README.md) for the full package list and usage. When adding a backend, follow [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md) — the umbrella package needs updates in 6 places.

### Gotchas

- **Async construction:** always `await createXSigner(...)` — direct class construction is deprecated and skips `init()`.
- **`signMessages` quirks (parity with Rust):** `CrossmintSigner` rejects with "not supported". `CdpSigner` requires UTF-8 message bytes.
- **HTTPS enforced:** all `apiBaseUrl` config fields must reject non-HTTPS URLs — validate with `assertHttpsUrl()` from `@solana/keychain-core`.
- **Remote API calls:** go through `fetchSignerJson()` from `@solana/keychain-core` — it owns the HTTP_ERROR/REMOTE_API_ERROR/PARSING_ERROR pipeline, response sanitization (`sanitizeRemoteErrorResponse()`), redirect rejection, and a default 60s timeout. Batch signing uses core `signBatchStaggered()` + `validateRequestDelayMs()`.
- **Integration tests:** use `runSignerIntegrationTest` + per-package `setup.ts`; spun up via `just ts-test-integration` (loads `.env`, starts local Vault).
- **Tree-shakability:** run `just ts-treeshake` after touching exports — every package and the umbrella must stay tree-shakable.
- **Adding a backend:** the umbrella package, `typescript-ci.yml`, and `typescript-publish.yml` all need updates (see [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md)).

## Branch Workflow

- `main` — integration branch (audited + unaudited).
- `feat/*`, `fix/*`, `chore/*` — topic branches from `main`.
- `hotfix/*` — urgent fixes from a deployed stable tag (use `just hotfix`).

`just branch-info` prints the full guidance.
