---
name: release
description: >
  Guide for releasing a new version of solana-keychain (Rust and/or TypeScript).
  Use when asked to "prepare a release", "bump the version", "release Rust", "release TypeScript",
  "publish a new version", or "cut a release". Covers the PR-based release flow end-to-end.
---

# Release Skill

Prepare and publish a new release of solana-keychain via a PR-based flow. The local `just release` / `just release-ts` commands handle version bumps and changelog generation; GitHub Actions handles tagging and publishing.

## Prerequisites

Ensure these tools are installed:

| Tool | Install |
|------|---------|
| `cargo-edit` (provides `cargo set-version`) | `cargo install cargo-edit` |
| `git-cliff` | `cargo install git-cliff` |
| `pnpm` | `npm install -g pnpm` |
| `gh` CLI | `brew install gh` |
| `jq` | `brew install jq` |

## Current Versions Reference

| Artifact | Version file | Field |
|----------|-------------|-------|
| Rust crate | `rust/Cargo.toml` | `version` |
| TypeScript packages | `typescript/packages/keychain/package.json` | `version` |

## Step 1: Pull latest changes on main

```bash
git checkout main
git pull
```

## Step 2: Run Rust release (on main)

```bash
just release
# When prompted, confirm and enter the new version (e.g. 0.5.0)
```

This runs `cargo set-version <version>` on `rust/Cargo.toml` and regenerates `rust/CHANGELOG.md` via `git-cliff`, then stages both files.

For pre-release versions use semver suffixes: `1.2.3-beta.1`, `1.2.3-rc.1`.

## Step 3: Run TypeScript release (on main)

```bash
just release-ts
# When prompted, confirm and enter the new version (e.g. 0.6.0)
```

This runs `npm version <version> --no-git-tag-version` on all 13 packages (core, aws-kms, cdp, dfns, fireblocks, gcp-kms, para, privy, turnkey, vault, keychain, test-utils, crossmint) plus the root workspace, then stages all changes.

## Step 4: Update Cargo.lock

`just release` stages `Cargo.toml` and `CHANGELOG.md` but does not update the lock file. CI runs with `--locked`, so a stale lock file will fail the build. Run:

```bash
cd rust && cargo update --workspace && cd ..
git add rust/Cargo.lock
```

## Step 5: Create release branch, commit, and push

```bash
git checkout -b chore/release-rust-vX.Y.Z-ts-vA.B.C
git commit -m "chore: release rust vX.Y.Z and ts-keychain vA.B.C"
git push -u origin chore/release-rust-vX.Y.Z-ts-vA.B.C
```

## Step 6: Open PR

```bash
gh pr create \
  --title "chore: release rust vX.Y.Z and ts-keychain vA.B.C" \
  --reviewer dev-jodee,amilz \
  --body "$(cat <<'EOF'
## Release

- Rust `solana-keychain` → vX.Y.Z ([CHANGELOG](rust/CHANGELOG.md))
- TypeScript `@solana/keychain` and packages → vA.B.C

## Post-merge

Manually trigger these GitHub Actions workflows after this PR merges to `main`:
1. **Publish Rust Crate** — creates `vX.Y.Z` tag, publishes to crates.io
2. **Publish TypeScript Packages (Manual)** — creates `ts-keychain-vA.B.C` tag, publishes all packages to npm
EOF
)"
```

## Step 7: Post-merge — Trigger GitHub Actions

After the PR merges to `main`:

1. Go to **GitHub Actions → "Publish Rust Crate"** → click **Run workflow** → select `main`
   - Creates git tag `vX.Y.Z`
   - Publishes to crates.io
2. Go to **GitHub Actions → "Publish TypeScript Packages (Manual)"** → click **Run workflow** → select `main`
   - Creates git tag `ts-keychain-vA.B.C`
   - Publishes all `@solana/keychain-*` packages to npm

## Verification

- Confirm `vX.Y.Z` tag exists on GitHub
- Confirm crates.io page shows new version
- Confirm `ts-keychain-vA.B.C` tag exists on GitHub
- Confirm `@solana/keychain` on npm shows new version

## Hotfix Note

For urgent fixes to a deployed stable version, use `just hotfix` instead of this flow:

```bash
just hotfix <fix-name>     # creates hotfix/<fix-name> from latest stable tag
# apply fixes, push, open PR to main
# after merge, run just release on main
```
