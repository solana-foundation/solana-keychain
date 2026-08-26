---
name: release
description: >
  Guide for releasing a new version of solana-keychain (Rust, TypeScript, Python, Go, in any combination).
  Use when asked to "prepare a release", "bump the version", "release Rust", "release TypeScript",
  "release Python", "release Go", "publish a new version", or "cut a release".
  Covers the PR-based release flow end-to-end, stable and pre-release.
---

# Release Skill

Prepare and publish a new release of solana-keychain via a PR-based flow. Release only the languages that changed; the four are independent, each with its own tag namespace and publish workflow.

## Publish Paths

- Mainline release: prepare release changes, open PR to `main`, merge, then publish from `main`.
- Hotfix release: create `hotfix/*` from deployed tag, prepare release on `hotfix/*`, publish from `hotfix/*`, then merge back to `main`.

| Tool | Install |
|------|---------|
| `cargo-edit` (`cargo set-version`) | `cargo install cargo-edit` |
| `pnpm` | `npm install -g pnpm` |
| `gh` CLI | `brew install gh` |
| `jq` | `brew install jq` |
| Go | `brew install go` |

## Versions, tags and workflows

| Language | Version file | Tag | Publish workflow |
|----------|--------------|-----|------------------|
| Rust | `rust/Cargo.toml` | `vX.Y.Z` | `Publish Rust Crate` |
| TypeScript | `typescript/packages/*/package.json` plus `typescript/package.json` | `ts-keychain-vX.Y.Z` | `Publish TypeScript Packages (Manual)` |
| Python | `python/pyproject.toml` | `python-vX.Y.Z` | `Publish Python Package (Manual)` |
| Go | none (the tag *is* the version) | `go/<module>/vX.Y.Z`, one per module | `Publish Go Modules (Manual)` |

Pre-release suffixes differ per ecosystem, and every workflow detects the pre-release from the version string:

| Language | Pre-release form | Consumer effect |
|----------|------------------|-----------------|
| Rust | `2.0.0-beta.1` | crates.io will not resolve it for a `^X` requirement; it has to be pinned |
| TypeScript | `2.0.0-beta.1` | published under the `beta` npm dist-tag, so `latest` is untouched |
| Python | `2.0.0b1` (PEP 440, not `-beta.1`) | needs a pin or `pip install --pre` |
| Go | `2.0.0-beta.1` | `@latest` skips it |

## Release notes

There are no changelog files. Each publish workflow creates the GitHub release itself, calling `generateReleaseNotes` with the previous tag *in that language's namespace*, so the PR list is scoped to that language's release range. Nothing to write by hand.

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

Also check whether the release branch already exists. If so, skip to Step 7:

```bash
git branch -a | grep release
```

---

## Step 2: Bump the Rust version

Skip if Rust is not part of this release.

```bash
cd rust && cargo set-version X.Y.Z && cd ..
```

---

## Step 3: Update Cargo.lock and commit the Rust change

This MUST happen before the TypeScript bump — `just release-ts` checks for a clean working tree and will fail if `Cargo.lock` is dirty.

```bash
cd rust && cargo update --workspace && cd ..
git add rust/Cargo.toml rust/Cargo.lock
git commit -m "chore: bump rust version to vX.Y.Z"
```

---

## Step 4: Bump the TypeScript versions

Skip if TypeScript is not part of this release. Every package plus the root must carry the same version: the publish workflow refuses to run when they disagree.

Derive the package list from the directory rather than hardcoding it: the set grows with every new backend, and a stale list silently skips bumping one.

```bash
cd typescript
for pkg in packages/*; do
  (cd "$pkg" && npm version "A.B.C" --no-git-tag-version)
done
npm version "A.B.C" --no-git-tag-version
cd ..
```

`pnpm-lock.yaml` needs no update: internal dependencies use `workspace:*`.

Then run `just ts-treeshake` if exports changed since the last release.

---

## Step 5: Bump the Python version

Skip if Python is not part of this release. Use the PEP 440 form for pre-releases (`2.0.0b1`, not `2.0.0-beta.1`).

```bash
sed -i '' 's/^version = ".*"$/version = "X.Y.Z"/' python/pyproject.toml
```

---

## Step 6: Pin the Go module requires

Skip if Go is not part of this release. `testutils` and all 14 signer modules require `core` (and `testutils`) at a version, and `Publish Go Modules (Manual)` refuses to tag unless every internal require names the version being released.

```bash
cd go
for mod in testutils/go.mod signers/*/go.mod; do
  dir=$(dirname "$mod")
  (cd "$dir" \
    && go mod edit -require=github.com/solana-foundation/solana-keychain/go/core/v2@vX.Y.Z \
    && (grep -q 'testutils/v2 v' go.mod && go mod edit -require=github.com/solana-foundation/solana-keychain/go/testutils/v2@vX.Y.Z || true) \
    && go mod tidy)
done
cd ..
```

Keep the `replace` directives in place. `just go-release-prep` drops them, but its `go mod tidy` then cannot resolve a version the module proxy has never seen, so it fails before the tags exist. A `replace` is ignored when the module is consumed as a dependency, so leaving it costs consumers nothing while keeping the build and `just go-test` green on the release branch.

Verify before committing:

```bash
just go-build && just go-test
```

---

## Step 7: Create the release branch, commit, push

Name the branch and the commits after whatever is actually in the release.

```bash
git checkout -b chore/release-vX.Y.Z
git add typescript/ python/ go/
git commit -m "chore: release vX.Y.Z"
git push -u origin chore/release-vX.Y.Z
```

If the branch already existed from a previous session, switch to it and verify it already has the right state before opening the PR.

---

## Step 8: Open the PR to main

```bash
gh pr create \
  --title "chore: release vX.Y.Z" \
  --reviewer dev-jodee,amilz \
  --body "$(cat <<'EOF'
## Release

- Rust \`solana-keychain\` to vX.Y.Z
- TypeScript \`@solana/keychain\` and packages to vA.B.C
- Python \`solana-keychain\` to X.Y.Z
- Go modules to vX.Y.Z

## Merge

For mainline releases, a reviewer will run the \`complete-release\` skill to review CI, approve, squash-merge, and trigger the publish workflows from \`main\`.
EOF
)"
```

Drop the lines for languages this release does not touch.

---

## Hotfix

For urgent fixes to a deployed stable version:

```bash
just hotfix <fix-name>   # creates hotfix/<fix-name> from latest stable tag
```

Apply the fix on `hotfix/*`, then run the same version-bump steps above on that branch. `just release` / `just release-ts` are still off limits here for the same TTY reason: use Steps 2 through 5 manually.

Publish from `hotfix/*` before merging back, then open a PR to `main` and merge the hotfix back.
