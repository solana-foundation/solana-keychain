---
name: complete-release
description: >
  Finalize a mainline solana-keychain release after the PR is approved: approve, squash-merge, and
  trigger the publish workflows for the languages in the release from main via gh CLI. Use when
  asked to "finalize release", "merge release PR", "complete release", "publish packages", or
  "approve and merge release".
---

# Complete Release Skill

This is the **reviewer** half of the mainline release flow. Run this after a release PR to `main` has been reviewed and is ready to merge.

Notes:
- This skill is mainline-only: it dispatches publish workflows from `main`.
- Hotfix releases are published from `hotfix/*` before merge-back and are handled in `.claude/skills/release/SKILL.md`.
- Publish workflows allow both `main` and `hotfix/*` refs.

## Prerequisites

- `gh` CLI installed and authenticated (`gh auth status`)
- You are a repo collaborator with write access

## Step 1: Identify the release PR

If a PR number is not provided, find it:

```bash
gh pr list --base main --state open | grep chore/release
```

Note the PR number (e.g. `42`).

## Step 2: Approve the PR

```bash
gh pr review <PR_NUMBER> --approve --body "LGTM"
```

## Step 3: Confirm CI is green, then squash merge

Check that all required status checks have passed before merging:

```bash
gh pr checks <PR_NUMBER>
```

All checks should show `pass`. Once green:

```bash
gh pr merge <PR_NUMBER> --squash --delete-branch
```

Wait for merge to complete before proceeding.

## Step 4: Detect what changed and trigger publish workflows from main

Check which paths the merged PR touched, then trigger only the relevant workflow(s):

Each language publishes through its own workflow. Trigger only the ones whose tree the release touched.

```bash
# Get the files changed by the merged PR
FILES=$(gh pr view <PR_NUMBER> --json files --jq '.files[].path')

for lang in rust typescript python go; do
  echo "$lang changed: $(echo "$FILES" | grep -q "^${lang}/" && echo yes || echo no)"
done
```

If Rust changed (`rust/Cargo.toml`, `rust/Cargo.lock`, etc.):

```bash
gh workflow run "Publish Rust Crate" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f publish-to-crates=true \
  -f create-github-release=true
```

If TypeScript changed (`typescript/packages/*/package.json`, etc.):

```bash
gh workflow run "Publish TypeScript Packages (Manual)" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f package=all \
  -f publish-to-npm=true \
  -f create-github-release=true
```

If Python changed (`python/pyproject.toml`, `python/CHANGELOG.md`, etc.):

```bash
gh workflow run "Publish Python Package (Manual)" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f publish-to-pypi=true \
  -f create-github-release=true
```

If Go changed. Unlike the others, this workflow takes the version explicitly, without a leading `v`, because Go modules carry no version file to read it from:

```bash
gh workflow run "Publish Go Modules (Manual)" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f version=A.B.C \
  -f create-github-release=true
```

## Step 5: Verify workflows started

Only check workflows that were triggered:

```bash
gh run list --workflow="<workflow name>" --limit 1
```

Each triggered workflow should show `queued` or `in_progress`.

## Verification

Once workflows complete, for each language published:

- Rust: `vX.Y.Z` tag exists on GitHub and crates.io shows the new version
- TypeScript: `ts-keychain-vA.B.C` tag exists on GitHub and `@solana/keychain` on npm shows the new version
- Python: `solana-keychain` on PyPI shows the new version
- Go: the per-module tags exist and `go get` resolves the new version
