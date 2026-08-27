---
name: release
description: >
  Guide for releasing a new version of solana-keychain (Rust, TypeScript, Python and/or Go).
  Use when asked to "prepare a release", "bump the version", "release Rust", "release TypeScript",
  "release Python", "release Go", "publish a new version", or "cut a release". Covers the PR-based
  release flow end-to-end.
---

# Release Skill

Prepare and publish a new release of solana-keychain via a PR-based flow.

## Publish Paths

- Mainline release: prepare release changes, open PR to `main`, merge, then publish from `main`.
- Hotfix release: create `hotfix/*` from deployed tag, prepare release on `hotfix/*`, publish from `hotfix/*`, then merge back to `main`.

Needs `cargo-edit` (for `cargo set-version`) and `git-cliff`, both `cargo install`.

## Where versions live

| Artifact | Version file |
|----------|-------------|
| Rust crate | `rust/Cargo.toml` |
| TypeScript packages | every `typescript/packages/*/package.json` plus `typescript/package.json` |
| Python package | `python/pyproject.toml` |
| Go modules | tags only; `just go-release-prep <version>` rewrites the module replace directives |

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

Commit this before touching the other languages. `Cargo.lock` moves whenever the crate version does, and a dirty lockfile fails the clean-working-tree check in `just release-ts` if anyone falls back to it.

```bash
cd rust && cargo update --workspace && cd ..
git add rust/Cargo.toml rust/CHANGELOG.md rust/Cargo.lock
git commit -m "chore: bump rust version to vX.Y.Z"
```

---

## Step 5: Bump TypeScript versions

Derive the package list from the directory rather than hardcoding it: the set grows with every new backend, and a stale list silently skips bumping one.

```bash
cd typescript
for dir in packages/*/; do
  (cd "$dir" && npm version "A.B.C" --no-git-tag-version)
done
npm version "A.B.C" --no-git-tag-version
cd ..
```

Confirm every package moved before continuing:

```bash
grep -h '"version"' typescript/package.json typescript/packages/*/package.json | sort -u
```

---

## Step 6: Bump Python and Go, if they are in this release

Release only the languages whose code changed; each publishes through its own workflow.

Python, if `python/` changed:

```bash
# python/pyproject.toml -> version = "A.B.C"
# add the release section to python/CHANGELOG.md
```

Go, if `go/` changed. Go modules carry no version file; the recipe rewrites each module's replace directives so the tagged modules resolve against each other:

```bash
just go-release-prep A.B.C
```

## Step 7: Create release branch, commit all changes, push

```bash
git checkout -b chore/release-rust-vX.Y.Z-ts-vA.B.C
git add -A
git commit -m "chore: release rust vX.Y.Z and ts-keychain vA.B.C"
git push -u origin chore/release-rust-vX.Y.Z-ts-vA.B.C
```

Name the branch and the commit after the languages actually in the release.

If the branch already existed from a previous session, switch to it and verify it already has the right state before opening the PR.

---

## Step 8: Open PR to main

```bash
gh pr create \
  --title "chore: release rust vX.Y.Z and ts-keychain vA.B.C" \
  --reviewer dev-jodee,amilz \
  --body "$(cat <<'EOF'
## Release

List only the languages in this release:

- Rust \`solana-keychain\` to vX.Y.Z ([CHANGELOG](rust/CHANGELOG.md))
- TypeScript \`@solana/keychain\` and packages to vA.B.C
- Python \`solana-keychain\` to vA.B.C ([CHANGELOG](python/CHANGELOG.md))
- Go modules to vA.B.C

## Merge

For mainline releases, a reviewer will run the \`complete-release\` skill to review CI, approve, squash-merge, and trigger publish workflows from \`main\`.
EOF
)"
```

---

## Hotfix

For urgent fixes to a deployed stable version:

```bash
just hotfix <fix-name>   # creates hotfix/<fix-name> from latest stable tag
```

Apply the fix on `hotfix/*`, then run the same version-bump steps above on that branch. `just release` / `just release-ts` are still off limits here for the same TTY reason: use Steps 2 through 5 manually.

Publish from `hotfix/*` before merging back, then open a PR to `main` and merge the hotfix back.
