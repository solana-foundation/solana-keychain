---
name: release
description: >
  Guide for releasing a new version of solana-keychain (Rust and/or TypeScript).
  Use when asked to "prepare a release", "bump the version", "release Rust", "release TypeScript",
  "publish a new version", or "cut a release". Covers the PR author half of the release flow:
  version bumps, changelog, branch, push, and open PR with reviewers.
---

# Release Skill

Prepare a release PR for solana-keychain. This is the **initialize** half of the release flow — it opens the PR and assigns reviewers. After the PR is approved and merged, use the `complete-release` skill to trigger publishing.

The local `just release` / `just release-ts` commands handle version bumps and changelog generation; GitHub Actions handles tagging and publishing.

## Step 0: Confirm scope

**Ask the user:** "Are you releasing Rust, TypeScript, or both?"

Use the answer to skip irrelevant steps below. The branch name, commit message, and PR body all vary by scope:

| Scope | Branch | Commit |
|-------|--------|--------|
| Rust only | `chore/release-rust-vX.Y.Z` | `chore: release rust vX.Y.Z` |
| TypeScript only | `chore/release-ts-vA.B.C` | `chore: release ts-keychain vA.B.C` |
| Both | `chore/release-rust-vX.Y.Z-ts-vA.B.C` | `chore: release rust vX.Y.Z and ts-keychain vA.B.C` |

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

## Step 2: Run Rust release (skip if TypeScript only)

```bash
just release
# When prompted, confirm and enter the new version (e.g. 0.5.0)
```

This runs `cargo set-version <version>` on `rust/Cargo.toml` and regenerates `rust/CHANGELOG.md` via `git-cliff`, then stages both files.

For pre-release versions use semver suffixes: `1.2.3-beta.1`, `1.2.3-rc.1`.

> **If releasing both Rust and TypeScript:** `just release` leaves staged files, and `just release-ts` requires a clean working directory. Commit the Rust changes before running Step 3:
> ```bash
> git commit -m "chore: bump rust version to vX.Y.Z"
> ```
> You will squash everything into one commit in Step 5.

## Step 3: Run TypeScript release (skip if Rust only)

```bash
just release-ts
# When prompted, confirm and enter the new version (e.g. 0.6.0)
```

This runs `npm version <version> --no-git-tag-version` on these packages plus the root workspace, then stages all changes:

```bash
PACKAGES="core aws-kms cdp dfns fireblocks gcp-kms para privy turnkey vault keychain test-utils crossmint"
```

## Step 4: Update Cargo.lock (skip if TypeScript only)

`just release` stages `Cargo.toml` and `CHANGELOG.md` but does not update the lock file. CI runs with `--locked`, so a stale lock file will fail the build. Run:

```bash
cd rust && cargo update --workspace && cd ..
git add rust/Cargo.lock
```

## Step 5: Create release branch, commit, and push

Use the branch name and commit message from the scope table in Step 0.

```bash
git checkout -b <branch-name>
git commit -m "<commit-message>"
git push -u origin <branch-name>
```

## Step 6: Open PR

Tailor the PR body to only list what was released:

```bash
gh pr create \
  --title "<commit-message>" \
  --reviewer dev-jodee,amilz \
  --body "$(cat <<'EOF'
## Release

<!-- Include only the lines that apply: -->
- Rust `solana-keychain` → vX.Y.Z ([CHANGELOG](rust/CHANGELOG.md))
- TypeScript `@solana/keychain` and packages → vA.B.C

## Merge

A reviewer will run the `complete-release` skill to review CI, approve, squash-merge, and trigger the publish workflows.
EOF
)"
```

## Next Step

After the PR is reviewed and approved, the reviewer runs the `complete-release` skill to squash-merge the PR and trigger the relevant publish workflow(s).

## Hotfix Note

For urgent fixes to a deployed stable version, use `just hotfix` instead of this flow:

```bash
just hotfix <fix-name>     # creates hotfix/<fix-name> from latest stable tag
# apply fixes, push, open PR to main
# after merge, run just release on main
```
