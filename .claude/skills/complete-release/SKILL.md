---
name: complete-release
description: >
  Finalize a solana-keychain release after the PR is approved: approve, squash-merge, and trigger
  both publish workflows via gh CLI. Use when asked to "finalize release", "merge release PR",
  "complete release", "publish packages", or "approve and merge release".
---

# Complete Release Skill

This is the **reviewer** half of the release flow. Run this after the release PR has been reviewed and is ready to merge.

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

## Step 3: Squash merge and delete the branch

```bash
gh pr merge <PR_NUMBER> --squash --delete-branch
```

Wait for merge to complete before proceeding.

## Step 4: Trigger Rust publish workflow

```bash
gh workflow run "Publish Rust Crate" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f publish-to-crates=true \
  -f create-github-release=true
```

## Step 5: Trigger TypeScript publish workflow

```bash
gh workflow run "Publish TypeScript Packages (Manual)" \
  --repo solana-foundation/solana-keychain \
  --ref main \
  -f package=all \
  -f publish-to-npm=true \
  -f create-github-release=true
```

## Step 6: Verify workflows started

```bash
gh run list --workflow="Publish Rust Crate" --limit 1
gh run list --workflow="Publish TypeScript Packages (Manual)" --limit 1
```

Both should show a run in `queued` or `in_progress` state.

## Verification

Once workflows complete:

- Confirm `vX.Y.Z` tag exists on GitHub
- Confirm crates.io page shows new version
- Confirm `ts-keychain-vA.B.C` tag exists on GitHub
- Confirm `@solana/keychain` on npm shows new version
