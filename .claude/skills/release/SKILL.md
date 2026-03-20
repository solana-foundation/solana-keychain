---
name: release
description: >
  Guide for releasing a new version of solana-keychain (Rust and/or TypeScript).
  Use when asked to "prepare a release", "bump the version", "release Rust", "release TypeScript",
  "publish a new version", or "cut a release". Covers the PR-based release flow end-to-end.
---

# Release Skill

Prepare and publish a new release of solana-keychain via a PR-based flow.

## Prerequisites

| Tool | Install |
|------|---------|
| `cargo-edit` (`cargo set-version`) | `cargo install cargo-edit` |
| `git-cliff` | `cargo install git-cliff` |
| `pnpm` | `npm install -g pnpm` |
| `gh` CLI | `brew install gh` |
| `jq` | `brew install jq` |

## Current Versions Reference

| Artifact | Version file | Field |
|----------|-------------|-------|
| Rust crate | `rust/Cargo.toml` | `version` |
| TypeScript packages | `typescript/packages/keychain/package.json` | `version` |

---

## IMPORTANT: Do NOT use `just release` / `just release-ts`

Both recipes use `[confirm]` + `read -p` for interactive prompts. They cannot be invoked non-interactively (stdin piping breaks them). Always use the manual steps below instead.

---

## Step 1: Pull latest main and verify clean state

```bash
git checkout main
git pull
git status  # must be clean before proceeding
```

Also check whether the release branch already exists — if so, skip to Step 6:

```bash
git branch -a | grep release
```

---

## Step 2: Bump Rust version

```bash
cd rust && cargo set-version X.Y.Z && cd ..
```

---

## Step 3: Generate CHANGELOG.md

Run from the **project root** (not from `rust/`):

```bash
last_tag=$(git tag -l "v*" --sort=-version:refname | head -1)
if [ -f rust/CHANGELOG.md ]; then
  git-cliff "${last_tag}..HEAD" --tag "vX.Y.Z" --config .github/cliff.toml --strip all > /tmp/CHANGELOG.new.md
  cat rust/CHANGELOG.md >> /tmp/CHANGELOG.new.md
  mv /tmp/CHANGELOG.new.md rust/CHANGELOG.md
else
  git-cliff "${last_tag}..HEAD" --tag "vX.Y.Z" --config .github/cliff.toml --output rust/CHANGELOG.md --strip all
fi
```

Review the output: `cat rust/CHANGELOG.md | head -30`

---

## Step 4: Update Cargo.lock and commit Rust changes

This MUST happen before the TS release — `just release-ts` checks for a clean working tree and will fail if `Cargo.lock` is dirty.

```bash
cd rust && cargo update --workspace && cd ..
git add rust/Cargo.toml rust/CHANGELOG.md rust/Cargo.lock
git commit -m "chore: bump rust version to vX.Y.Z"
```

---

## Step 5: Bump TypeScript versions

```bash
cd typescript
for pkg in core aws-kms cdp dfns fireblocks gcp-kms para privy turnkey vault keychain test-utils crossmint; do
  cd packages/${pkg} && npm version "A.B.C" --no-git-tag-version && cd ../..
done
npm version "A.B.C" --no-git-tag-version
cd ..
```

---

## Step 6: Create release branch, commit all changes, push

```bash
git checkout -b chore/release-rust-vX.Y.Z-ts-vA.B.C
git add typescript/
git commit -m "chore: release rust vX.Y.Z and ts-keychain vA.B.C"
git push -u origin chore/release-rust-vX.Y.Z-ts-vA.B.C
```

If the branch already existed from a previous session, switch to it and verify it already has the right state before opening the PR.

---

## Step 7: Open PR

```bash
gh pr create \
  --title "chore: release rust vX.Y.Z and ts-keychain vA.B.C" \
  --reviewer dev-jodee,amilz \
  --body "$(cat <<'EOF'
## Release

- Rust \`solana-keychain\` → vX.Y.Z ([CHANGELOG](rust/CHANGELOG.md))
- TypeScript \`@solana/keychain\` and packages → vA.B.C

## Merge

A reviewer will run the \`complete-release\` skill to review CI, approve, squash-merge, and trigger the publish workflows.
EOF
)"
```

---

## Hotfix

For urgent fixes to a deployed stable version:

```bash
just hotfix <fix-name>   # creates hotfix/<fix-name> from latest stable tag
# apply fixes, push, open PR to main
# after merge, run this release flow on main
```
