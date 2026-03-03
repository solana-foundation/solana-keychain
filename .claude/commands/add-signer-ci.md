---
description: Add a new signer backend to all CI workflow files
allowed-tools: Read, Edit, Glob, Grep
---

# Add Signer to CI

Add the signer described in `$ARGUMENTS` to all CI workflow files. If arguments are missing, ask the user for: signer display name, Rust feature name, Rust integration test function name, TypeScript package name, and required environment variable names.

## Files to Update

You MUST update all 6 locations below. Read each file first, then make edits that match the existing patterns exactly.

### 1. `.github/workflows/ci.yml` — Rust CI

**a) Unit test backend matrix** (`rust-test` job → `strategy.matrix.backend`):
Add the Rust feature name to the backend array, before `all`.

**b) Integration test matrix** (`rust-integration-test` job → `strategy.matrix.test`):
Add the Rust integration test function name (e.g., `test_<name>_integration`) to the test array.

**c) Integration test env vars** (`rust-integration-test` job → env block):
Add the signer's env vars after the last existing signer's env vars, before `SOLANA_RPC_URL`.

### 2. `.github/workflows/fork-external-live-manual.yml` — Fork External Live Tests

**a) Rust test step env vars** (`Run Rust external live integration tests` → env block):
Add the signer's env vars after the last existing signer's env vars, before `SOLANA_RPC_URL`.

**b) Rust test step tests array** (same step → `tests=()` bash array):
Add the Rust integration test function name to the array.

**c) TypeScript test step env vars** (`Run TypeScript external live integration tests` → env block):
Add the signer's env vars (if the signer has a TypeScript package).

**d) TypeScript test step packages array** (same step → `packages=()` bash array):
Add the TypeScript package name (if applicable).

### 3. `.github/workflows/typescript-ci.yml` — TypeScript CI (if TS package exists)

**a) Unit test matrix** (`typescript-test-unit` job → `strategy.matrix.package`):
Add the TypeScript package name.

**b) Integration test matrix** (`typescript-test-integration` job → `strategy.matrix.package`):
Add the TypeScript package name.

**c) Integration test env vars** (integration test step → env block):
Add a comment header and the signer's env vars.

### 4. `.github/workflows/typescript-publish.yml` — TypeScript Publish (if TS package exists)

**a) `PUBLISH_PACKAGES` env list**:
Add the package name in dependency order (before `keychain` umbrella).

**b) GitHub Release `packages` array** (in the `actions/github-script` step):
Add `@solana/keychain-<name>` to the array.

**c) Publish summary table**:
Add a row for the new package.

### 5. `rust/Cargo.toml` — Feature flags

**a) Feature declarations**: Add the new signer's feature with its dependencies.
**b) `all` feature group**: Add the new feature name to the `all` list.

### 6. `rust/src/tests/mod.rs` — Test module

Add a `#[cfg(feature = "<name>")]` gated module declaration for the integration test module.

## GitHub Secrets Reminder

After updating CI files, the following secrets must be configured:

- **Repository level** (Settings → Secrets → Actions): for `ci.yml` workflows
- **`external-live-tests` environment** (Settings → Environments → external-live-tests → Secrets): for `fork-external-live-manual.yml`

Both locations need the same secret names configured.

## Verification

After making all changes:
1. Confirm the new signer appears in `ci.yml` backend matrix, integration test matrix, and env vars
2. Confirm the new signer appears in `fork-external-live-manual.yml` env vars and test arrays (both Rust and TS if applicable)
3. Confirm the new signer appears in `typescript-ci.yml` matrices and env vars (if applicable)
4. Confirm the new signer appears in `typescript-publish.yml` package lists (if applicable)
5. Confirm `rust/Cargo.toml` has the feature flag and it's in the `all` group
6. Confirm `rust/src/tests/mod.rs` has the test module declaration
