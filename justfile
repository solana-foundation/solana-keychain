set shell := ["bash", "-uc"]

sdkv2 := "all,sdk-v2,unsafe-debug"
sdkv3 := "all,sdk-v3,unsafe-debug"
sdkv2_int := "all,sdk-v2,unsafe-debug,integration-tests"
sdkv3_int := "all,sdk-v3,unsafe-debug,integration-tests"
integration_tests := "test_fireblocks_integration test_privy_integration test_turnkey_integration test_vault_integration"

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
    pnpm -F @solana-keychain/fireblocks -F @solana-keychain/privy -F @solana-keychain/turnkey -F @solana-keychain/vault test:integration

# ===========================================================
# ========================= Release =========================
# ===========================================================
[confirm("This will bump version and stage changes. Continue?")]
[working-directory: 'rust']
release version: _check-release-tools
    #!/usr/bin/env bash
    set -euo pipefail

    current_version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
    echo "Current version: ${current_version}"
    echo "New version: {{ version }}"

    cargo set-version {{ version }}

    echo "Generating CHANGELOG.md..."
    last_tag=$(git tag -l "v*" --sort=-version:refname | head -1)
    if [ -z "${last_tag}" ]; then
        git-cliff $(git rev-list --max-parents=0 HEAD)..HEAD --tag "v{{ version }}" --config ../.github/cliff.toml --output CHANGELOG.md --strip all
    else
        if [ -f CHANGELOG.md ]; then
            git-cliff "${last_tag}..HEAD" --tag "v{{ version }}" --config ../.github/cliff.toml --strip all > CHANGELOG.new.md
            cat CHANGELOG.md >> CHANGELOG.new.md
            mv CHANGELOG.new.md CHANGELOG.md
        else
            git-cliff "${last_tag}..HEAD" --tag "v{{ version }}" --config ../.github/cliff.toml --output CHANGELOG.md --strip all
        fi
    fi

    git add Cargo.toml CHANGELOG.md

    echo ""
    echo "Release prepared! Next steps:"
    echo "  1. Review CHANGELOG.md"
    echo "  2. git commit -m 'chore: release v{{ version }}'"
    echo "  3. git push"
    echo "  4. Trigger 'Publish Rust Crate' workflow"

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
