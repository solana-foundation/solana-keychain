---
name: add-signer-ci
description: >
  Prepare CI workflows for a new signer backend contributed via a fork PR. Use
  when asked to "add a signer to CI", "wire up CI for a new signer", "prepare
  the fork external live tests", or when a new signing backend needs its
  workflow matrices, env vars, and publish entries added.
allowed-tools: Read, Edit, Glob, Grep
---

# Add Fork Signer to CI

Prepare CI workflows for a new signer being added via a fork PR. This is a two-phase process because fork PRs can't use repository secrets, so `fork-external-live-manual.yml` (which runs from `main`'s YAML) must be updated on `main` first.

If any of these are unknown, ask the user for: signer display name, Rust feature name, Rust integration test function name, TypeScript package name (if any), and required environment variable names.

## Phase 1 — Our Preparatory PR (merged to `main`)

This is what YOU do. Read each file first, then make edits matching existing patterns exactly.

### 1. `.github/workflows/fork-external-live-manual.yml`

**a) Rust test step env vars** (`Run Rust external live integration tests` → env block):
Add the signer's env vars after the last existing signer's env vars, before `SOLANA_RPC_URL`.

**b) Rust test step tests array** (same step → `tests=()` bash array):
Add the Rust integration test function name to the array.

**c) TypeScript test step env vars** (`Run TypeScript external live integration tests` → env block):
Add the signer's env vars (if the signer has a TypeScript package).

**d) TypeScript test step packages array** (same step → `packages=()` bash array):
Add the TypeScript package name (if applicable).

### 2. `.github/workflows/ci.yml` — env vars ONLY

**Integration test env vars** (`rust-integration-test` job → env block):
Add the signer's env vars after the last existing signer's env vars, before `SOLANA_RPC_URL`.

**DO NOT** add to the `backend` matrix or `test` matrix. The Rust feature and test don't exist on `main` yet — adding them would break CI. Those go in Phase 2.

## Phase 2 — Fork Contributor Adds to Their PR

Tell the fork contributor (in a PR comment or issue) to add these to their branch alongside the signer code:

### 1. `.github/workflows/ci.yml`

**a) Unit test backend matrix** (`rust-test` job → `strategy.matrix.backend`):
Add the Rust feature name to the backend array, before `all`.

**b) Integration test matrix** (`rust-integration-test` job → `strategy.matrix.test`):
Add the integration test function name to the test array.

### 2. `.github/workflows/typescript-ci.yml` (if TS package exists)

**a) Unit test matrix** (`typescript-test-unit` job → `strategy.matrix.package`):
Add the TypeScript package name.

**b) Integration test matrix** (`typescript-test-integration` job → `strategy.matrix.package`):
Add the TypeScript package name.

**c) Integration test env vars** (integration test step → env block):
Add a comment header and the signer's env vars.

### 3. `.github/workflows/typescript-publish.yml` (if TS package exists)

**a) `PUBLISH_PACKAGES` env list**:
Add the package name in dependency order (before `keychain` umbrella).

**b) GitHub Release `packages` array** (in the `actions/github-script` step):
Add `@solana/keychain-<name>` to the array.

**c) Publish summary table**:
Add a row for the new package.

## Merge Order

1. Merge Phase 1 PR → `main` is ready with secrets wired up
2. Trigger `Fork External Live Tests` workflow with the fork PR number → integration tests run with secrets
3. Merge the fork PR (Phase 2 changes included alongside the code)

## GitHub Secrets Reminder

After updating CI files, the following secrets must be configured:

- **Repository level** (Settings → Secrets → Actions): for `ci.yml` workflows
- **`external-live-tests` environment** (Settings → Environments → external-live-tests → Secrets): for `fork-external-live-manual.yml`

Both locations need the same secret names configured.

## Verification

After making Phase 1 changes:
1. Confirm `fork-external-live-manual.yml` has the new env vars and test entries (Rust and TS if applicable)
2. Confirm `ci.yml` has the new env vars but NOT the matrix additions
3. Confirm CI passes (no references to nonexistent features)
