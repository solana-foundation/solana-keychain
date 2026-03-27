set shell := ["bash", "-uc"]

sdkv2 := "all,sdk-v2,unsafe-debug"
sdkv3 := "all,sdk-v3,unsafe-debug"
sdkv2_int := "all,sdk-v2,unsafe-debug,integration-tests"
sdkv3_int := "all,sdk-v3,unsafe-debug,integration-tests"
integration_tests := "test_fireblocks_integration test_privy_integration test_turnkey_integration test_vault_integration test_aws_kms_integration"

default:
    @just --list

# Format and lint
fmt: rust-fmt ts-fmt

# Build
build: rust-build ts-build

# Unit tests
test: rust-test ts-test

# Integration tests
test-integration: rust-test-integration ts-test-integration

# All tests
test-all: test test-integration

# ===========================================================
# =========================== Rust ==========================
# ===========================================================

[working-directory: 'rust']
rust-fmt:
    cargo fmt
    cargo clippy --all-targets --no-default-features --features {{ sdkv2_int }} -- -D warnings
    cargo clippy --all-targets --no-default-features --features {{ sdkv3_int }} -- -D warnings

[working-directory: 'rust']
rust-build:
    cargo build --no-default-features --features all,sdk-v2
    cargo build --no-default-features --features all,sdk-v3

[working-directory: 'rust']
rust-test:
    cargo test --no-default-features --features {{ sdkv2 }}
    cargo test --no-default-features --features {{ sdkv3 }}

[working-directory: 'rust']
rust-test-integration:
    #!/usr/bin/env bash
    set -euo pipefail

    VAULT_PID=""

    cleanup() {
        if [ -n "$VAULT_PID" ]; then
            echo "Stopping Vault dev server..."
            kill "$VAULT_PID" 2>/dev/null || true
            wait "$VAULT_PID" 2>/dev/null || true
        fi
        pkill -f "vault server -dev" 2>/dev/null || true
    }
    trap cleanup EXIT

    # Kill any existing vault dev server
    pkill -f "vault server -dev" 2>/dev/null || true

    # Load env vars from .env file
    if [ -f ../.env ]; then
        set -a
        source ../.env
        set +a
    fi

    # Start Vault in dev mode
    echo "Starting Vault dev server..."
    vault server -dev -dev-root-token-id="root" &
    VAULT_PID=$!

    # Set Vault environment variables
    export VAULT_ADDR='http://127.0.0.1:8200'
    export VAULT_TOKEN='root'

    # Wait for Vault API
    echo "Waiting for Vault to be ready..."
    for i in {1..10}; do
        if vault status > /dev/null 2>&1; then
            echo "Vault is ready!"
            break
        fi
        [[ $i -eq 10 ]] && { echo "Error: Vault not available"; exit 1; }
        sleep 1
    done

    # Setup transit engine and test key
    vault secrets enable transit >/dev/null 2>&1 || true
    vault write transit/restore/solana-test-key backup=@"src/tests/vault-test-key.b64" >/dev/null 2>&1 || true

    # Run integration tests
    echo "Running integration tests..."
    for test in {{ integration_tests }}; do
        cargo test --no-default-features --features {{ sdkv2_int }} "tests::${test}::"
    done
    for test in {{ integration_tests }}; do
        cargo test --no-default-features --features {{ sdkv3_int }} "tests::${test}::"
    done

# ===========================================================
# ======================== TypeScript =======================
# ===========================================================

[working-directory: 'typescript']
ts-fmt:
    pnpm lint:fix
    pnpm format

[working-directory: 'typescript']
ts-build:
    pnpm build

[working-directory: 'typescript']
ts-test:
    pnpm test:unit

# Tree-shake verification (requires build first)
[working-directory: 'typescript']
ts-treeshake: ts-build
    pnpm test:treeshakability
    node scripts/test-treeshake-umbrella.mjs

[working-directory: 'typescript']
ts-test-integration:
    #!/usr/bin/env bash
    set -euo pipefail

    VAULT_PID=""

    cleanup() {
        if [ -n "$VAULT_PID" ]; then
            echo "Stopping Vault dev server..."
            kill "$VAULT_PID" 2>/dev/null || true
            wait "$VAULT_PID" 2>/dev/null || true
        fi
        pkill -f "vault server -dev" 2>/dev/null || true
    }
    trap cleanup EXIT

    pkill -f "vault server -dev" 2>/dev/null || true

    # Load env vars from .env file
    if [ -f ../.env ]; then
        set -a
        source ../.env
        set +a
    fi

    echo "Starting Vault dev server..."
    vault server -dev -dev-root-token-id="root" &
    VAULT_PID=$!

    # Set Vault environment variables
    export VAULT_ADDR='http://127.0.0.1:8200'
    export VAULT_TOKEN='root'

    echo "Waiting for Vault to be ready..."
    for i in {1..10}; do
        if vault status > /dev/null 2>&1; then
            echo "Vault is ready!"
            break
        fi
        [[ $i -eq 10 ]] && { echo "Error: Vault not available"; exit 1; }
        sleep 1
    done

    vault secrets enable transit >/dev/null 2>&1 || true
    vault write transit/restore/solana-test-key backup=@"../rust/src/tests/vault-test-key.b64" >/dev/null 2>&1 || true

    echo "Running TypeScript integration tests..."
    pnpm -F @solana/keychain-fireblocks -F @solana/keychain-privy -F @solana/keychain-turnkey -F @solana/keychain-vault test:integration

# ===========================================================
# ========================= Release =========================
# ===========================================================

# Show branch workflow guidance
branch-info:
    @echo "Branch Workflow:"
    @echo "  main                → Integration branch (audited + unaudited commits)"
    @echo "  feat/*,fix/*,chore/* → Topic branches from main"
    @echo "  hotfix/*            → Urgent fixes from deployed stable tag"
    @echo ""
    @echo "Releasing:"
    @echo "  Stable/Beta/RC: checkout main, run 'just release'"
    @echo "  Pre-release versions use semver suffixes (e.g. 2.3.0-beta.1)"
    @echo "  Hotfix: run 'just hotfix' from deployed stable tag, then run 'just release' from hotfix/*"

# Prepare a new release (run from main or hotfix/*; use semver pre-release suffixes for beta/rc)
[confirm("Start release process?")]
[working-directory: 'rust']
release: _check-release-tools
    #!/usr/bin/env bash
    set -euo pipefail

    current_branch=$(git rev-parse --abbrev-ref HEAD)
    case "$current_branch" in
        main|hotfix/*) ;;
        *)
            echo "Error: Releases must be prepared from main or hotfix/* (current branch: $current_branch)"
            exit 1
            ;;
    esac

    current_version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
    echo "Current version: ${current_version}"

    read -p "New version: " version
    [ -z "$version" ] && { echo "Version required"; exit 1; }

    echo "Updating to $version..."
    cargo set-version "$version"

    echo "Generating CHANGELOG.md..."
    last_tag=$(git tag -l "v*" --sort=-version:refname | head -1)
    if [ -z "${last_tag}" ]; then
        git-cliff $(git rev-list --max-parents=0 HEAD)..HEAD --tag "v$version" --config ../.github/cliff.toml --output CHANGELOG.md --strip all
    else
        if [ -f CHANGELOG.md ]; then
            git-cliff "${last_tag}..HEAD" --tag "v$version" --config ../.github/cliff.toml --strip all > CHANGELOG.new.md
            cat CHANGELOG.md >> CHANGELOG.new.md
            mv CHANGELOG.new.md CHANGELOG.md
        else
            git-cliff "${last_tag}..HEAD" --tag "v$version" --config ../.github/cliff.toml --output CHANGELOG.md --strip all
        fi
    fi

    git add Cargo.toml CHANGELOG.md

    echo ""
    echo "Release prepared! Next steps:"
    echo "  1. Review CHANGELOG.md"
    echo "  2. git commit -m 'chore: release v$version'"
    echo "  3. git push origin HEAD"
    if [[ "$current_branch" == hotfix/* ]]; then
        echo "  4. Trigger 'Publish Rust Crate' workflow from this hotfix branch"
        echo "  5. Trigger 'Publish TypeScript Packages' workflow from this hotfix branch (if needed)"
        echo "  6. Merge hotfix back to main"
    else
        echo "  4. Trigger 'Publish Rust Crate' workflow from main"
    fi

# Start a hotfix branch from a deployed stable tag
hotfix name='' base_tag='':
    #!/usr/bin/env bash
    set -euo pipefail

    if [ -z "{{name}}" ]; then
        read -p "Hotfix branch name (without 'hotfix/'): " name
        [ -z "$name" ] && { echo "Name required"; exit 1; }
    else
        name="{{name}}"
    fi

    name="${name#hotfix/}"
    branch_name="hotfix/$name"

    git fetch --tags origin

    latest_tag=$(git tag -l "v*" --sort=-version:refname | head -1)
    if [ -z "{{base_tag}}" ]; then
        read -p "Base deployed tag [$latest_tag]: " base_tag
        base_tag="${base_tag:-$latest_tag}"
    else
        base_tag="{{base_tag}}"
    fi

    if [ -z "$base_tag" ]; then
        echo "Error: Base tag required"
        exit 1
    fi

    if ! git rev-parse -q --verify "refs/tags/$base_tag" >/dev/null; then
        if [[ "$base_tag" != v* ]] && git rev-parse -q --verify "refs/tags/v$base_tag" >/dev/null; then
            base_tag="v$base_tag"
        else
            echo "Error: Tag '$base_tag' not found"
            exit 1
        fi
    fi

    # Check if branch already exists
    if git show-ref --verify --quiet "refs/heads/$branch_name"; then
        echo "Branch $branch_name already exists"
        read -p "Switch to it? [y/N] " switch
        if [[ "$switch" =~ ^[Yy]$ ]]; then
            git checkout "$branch_name"
        fi
    elif git show-ref --verify --quiet "refs/remotes/origin/$branch_name"; then
        echo "Remote branch origin/$branch_name already exists"
        read -p "Create local tracking branch? [y/N] " track
        if [[ "$track" =~ ^[Yy]$ ]]; then
            git checkout -b "$branch_name" --track "origin/$branch_name"
        fi
    else
        read -p "Create branch $branch_name from tag $base_tag? [y/N] " create
        if [[ "$create" =~ ^[Yy]$ ]]; then
            git checkout -b "$branch_name" "$base_tag"
            echo ""
            echo "Created $branch_name from tag $base_tag"
        else
            echo "Aborted"
            exit 0
        fi
    fi

    echo ""
    echo "Next steps:"
    echo "  1. Apply your hotfix commits on $branch_name"
    echo "  2. Run 'just release' (and 'just release-ts' if needed) on $branch_name"
    echo "  3. Commit and push $branch_name"
    echo "  4. Trigger publish workflows from $branch_name"
    echo "  5. Merge $branch_name back to main"

# Bump TypeScript package versions and prepare for release (run from main or hotfix/*)
[confirm("This will bump all TypeScript package versions. Continue?")]
[working-directory: 'typescript']
release-ts: _check-ts-release
    #!/usr/bin/env bash
    set -euo pipefail

    current_branch=$(git rev-parse --abbrev-ref HEAD)
    case "$current_branch" in
        main|hotfix/*) ;;
        *)
            echo "Error: TypeScript releases must be prepared from main or hotfix/* (current branch: $current_branch)"
            exit 1
            ;;
    esac

    current_version=$(node -p "require('./packages/keychain/package.json').version")
    echo "Current version: ${current_version}"

    read -p "New version: " version
    [ -z "$version" ] && { echo "Version required"; exit 1; }

    echo "Updating to $version..."

    # Update version in all packages
    PACKAGES="core aws-kms cdp dfns fireblocks gcp-kms para privy turnkey vault keychain test-utils crossmint"
    for pkg in $PACKAGES; do
        echo "  Updating packages/${pkg}..."
        cd packages/${pkg}
        npm version "$version" --no-git-tag-version
        cd ../..
    done

    # Update root workspace version
    npm version "$version" --no-git-tag-version

    git add .

    echo ""
    echo "TypeScript release prepared! Next steps:"
    echo "  1. git commit -m 'chore(ts): release v$version'"
    echo "  2. git push origin HEAD"
    if [[ "$current_branch" == hotfix/* ]]; then
        echo "  3. Trigger 'Publish TypeScript Packages' workflow from this hotfix branch"
        echo "  4. Merge hotfix back to main"
    else
        echo "  3. Trigger 'Publish TypeScript Packages' workflow in GitHub Actions"
    fi

[private]
_check-ts-release:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: Working directory not clean"
        exit 1
    fi

[private]
_check-release-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: Working directory not clean"
        exit 1
    fi
    command -v cargo-set-version >/dev/null || { echo "Install: cargo install cargo-edit"; exit 1; }
    command -v git-cliff >/dev/null || { echo "Install: cargo install git-cliff"; exit 1; }
