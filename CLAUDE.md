# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`solana-keychain` is a Rust library providing a unified interface for signing Solana transactions across multiple backend implementations. The architecture centers around a single `SolanaSigner` trait that abstracts over nine different signing backends: Memory (local keypairs), Vault (HashiCorp), Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, and Crossmint.

## Common Commands

### Build and Test
```bash
# Build the project (default features only - memory signer)
cd rust && cargo build

# Build with all features
cd rust && cargo build --all-features

# Run tests (requires all features for complete test coverage)
cd rust && cargo test --all-features

# Run tests for a specific signer backend
cd rust && cargo test --features memory
cd rust && cargo test --features vault
cd rust && cargo test --features privy
cd rust && cargo test --features turnkey
cd rust && cargo test --features aws_kms
cd rust && cargo test --features fireblocks
cd rust && cargo test --features gcp_kms
cd rust && cargo test --features dfns
cd rust && cargo test --features crossmint

# Run a single test
cd rust && cargo test test_name --all-features

# Or use just (runs from project root)
just build
just test
```

### Linting and Formatting
```bash
# Format and lint code (runs clippy with all warnings as errors)
just fmt

# Just format code
cd rust && cargo fmt

# Just run clippy
cd rust && cargo clippy --all-targets --all-features -- -D warnings
```

### Branch Workflow
```bash
# Show branch workflow guidance
just branch-info

# Branch strategy:
#   main                → Integration branch (audited + unaudited commits)
#   feat/*,fix/*,chore/* → Topic branches from main
#   hotfix/*            → Urgent fixes from deployed stable tag
```

### Publishing a Rust Release (Mainline)
```bash
# Prepare a new release (prompts for version, generates CHANGELOG, stages changes)
# Mainline path: run from main after release PR merge
just release

# Review the CHANGELOG.md, then commit
git commit -m "chore: release vX.Y.Z"

# Push to GitHub
git push origin HEAD

# Manually trigger "Publish Rust Crate" from main
# Publish workflows run from the ref you dispatch
```

### Publishing a TypeScript Release (Mainline)
```bash
# Prepare a new TypeScript SDK release (prompts for version)
# Mainline path: run from main after release PR merge
just release-ts

# Commit and push
git commit -m "chore: release ts-keychain vX.Y.Z"
git push origin HEAD

# Manually trigger "Publish TypeScript Packages (Manual)" from main
```

### Creating a Hotfix Release
```bash
# Create a hotfix branch from a deployed stable tag
just hotfix              # prompts for name
just hotfix fix-auth     # pass name directly
just hotfix fix-auth v1.2.3 # optionally pass base tag

# On hotfix/*: apply fixes and prepare release
just release             # required for Rust publish
just release-ts          # if TypeScript packages changed

# Commit and push hotfix branch
git push origin HEAD

# Trigger publish workflows from hotfix/* before merge-back
# Then open PR from hotfix/* to main and merge back
```

Release skill references for agents:
- `.claude/skills/release/SKILL.md`
- `.claude/skills/complete-release/SKILL.md`

## Architecture

### Core Trait System

The library is built around the `SolanaSigner` trait ([rust/src/traits.rs](rust/src/traits.rs)) which defines the interface all signers must implement:
- `pubkey()` - Returns the signer's public key
- `sign_transaction()` - Signs a Solana transaction, modifying it in place
- `sign_message()` - Signs arbitrary bytes
- `is_available()` - Checks if the signer backend is healthy/reachable

### Unified Signer Enum

[rust/src/lib.rs](rust/src/lib.rs) provides a `Signer` enum that wraps all backend implementations, allowing runtime selection of signing backends while maintaining a single interface. Each variant corresponds to a feature-gated backend.

### Backend Implementations

All signers follow a consistent pattern but differ in where keys are stored:

1. **MemorySigner** ([rust/src/memory/mod.rs](rust/src/memory/mod.rs))
   - Stores keypair in memory
   - Supports multiple input formats: Base58, U8Array string, or JSON file path
   - Always available (no remote dependencies)
   - See [rust/src/memory/keypair_util.rs](rust/src/memory/keypair_util.rs) for key parsing logic

2. **VaultSigner** ([rust/src/vault/mod.rs](rust/src/vault/mod.rs))
   - Uses HashiCorp Vault's Transit engine for signing
   - Public key provided at construction (must match Vault key)
   - Uses `vaultrs` client library
   - Availability checked via key metadata read

3. **PrivySigner** ([rust/src/privy/mod.rs](rust/src/privy/mod.rs))
   - Requires `init()` call after construction to fetch public key
   - Uses Basic Auth with app_id:app_secret
   - RPC-style API with `signTransaction` method
   - Returns full signed transaction, extracts signature

4. **TurnkeySigner** ([rust/src/turnkey/mod.rs](rust/src/turnkey/mod.rs))
   - Uses P256 ECDSA signing for API authentication (X-Stamp header)
   - Signs raw payloads with hex encoding
   - Response contains r,s signature components that must be padded to 32 bytes each
   - Availability checked via `whoami` endpoint

5. **AWS KMS** ([rust/src/aws_kms/mod.rs](rust/src/aws_kms/mod.rs))
   - Uses AWS SDK with EdDSA (Ed25519) signing
   - Automatic credential discovery via environment or IAM
   - Availability checked via `DescribeKey`

6. **FireblocksSigner** ([rust/src/fireblocks/mod.rs](rust/src/fireblocks/mod.rs))
   - Uses Fireblocks API with EdDSA (Ed25519) signing
   - Requires `init()` to fetch public key before use
   - JWT-based authentication
   - Availability checked via user details endpoint

7. **GCP KMS** ([rust/src/gcp_kms/mod.rs](rust/src/gcp_kms/mod.rs))
   - Uses Google Cloud SDK with EdDSA (Ed25519) signing
   - PureEdDSA mode with `EC_SIGN_ED25519` algorithm
   - Automatic credential discovery via ADC
   - Availability checked via `GetCryptoKeyVersion`

8. **DfnsSigner** ([rust/src/dfns/mod.rs](rust/src/dfns/mod.rs))
     - Uses Dfns API signing
     - Requires `init()` to fetch wallet public key before use
     - User Action Signing flow: 3-step challenge/response
     - Signature returned as r+s hex components, concatenated to 64-byte Ed25519 signature
     - Authentication via private key in PEM format
     - Availability checked via wallet GET endpoint

9. **CrossmintSigner** ([rust/src/crossmint/mod.rs](rust/src/crossmint/mod.rs))
    - Uses Crossmint Wallets API with managed transaction signing flow
    - Supports Solana `smart` and `mpc` wallet types
    - Requires `init()` to resolve wallet and signer public key before use
    - `sign_message` is intentionally unsupported and returns a signing error
    - Availability checked via wallet GET endpoint

### Error Handling

All errors are centralized in [rust/src/error.rs](rust/src/error.rs) using `thiserror`. The `SignerError` enum covers key formats, signing failures, remote API errors, serialization, and configuration issues.

### Feature Flags

The library uses Cargo features for zero-cost abstraction:
- `memory` (default) - Only includes MemorySigner
- `vault` - Adds VaultSigner with reqwest, vaultrs, base64
- `privy` - Adds PrivySigner with reqwest, base64
- `turnkey` - Adds TurnkeySigner with reqwest, base64, p256, hex, chrono
- `aws_kms` - Adds KmsSigner with aws-sdk-kms
- `fireblocks` - Adds FireblocksSigner with reqwest, jsonwebtoken
- `gcp_kms` - Adds GcpKmsSigner with google-cloud-kms-v1, google-cloud-auth
- `dfns` - Adds DfnsSigner with reqwest, hex, ed25519-dalek
- `crossmint` - Adds CrossmintSigner with reqwest
- `all` - Enables all backends

At least one feature must be enabled (enforced by `compile_error!` in lib.rs).

## Testing

Tests are co-located with implementation code in each module. Remote signers (Vault, Privy, Turnkey, AWS, Fireblocks, GCP, DFNS, Crossmint) use `wiremock` to mock HTTP endpoints, avoiding actual API calls during testing. Tests cover:
- Constructor validation (invalid keys, etc.)
- Successful signing operations
- Error cases (unauthorized, malformed responses)
- Availability checks

Run specific backend tests:
```bash
cd rust && cargo test --features vault vault::tests
cd rust && cargo test --features privy privy::tests
cd rust && cargo test --features turnkey turnkey::tests
cd rust && cargo test --features aws_kms aws_kms::tests
cd rust && cargo test --features fireblocks fireblocks::tests
cd rust && cargo test --features gcp_kms gcp_kms::tests
cd rust && cargo test --features dfns dfns::tests
cd rust && cargo test --features crossmint crossmint::tests
```

## Key Implementation Notes

- All signers serialize transactions with `bincode` before signing
- Privy and Turnkey use Base64 encoding for payloads/responses
- Vault uses Base64 for both input and output
- Turnkey requires special handling for signature component padding (see [rust/src/turnkey/mod.rs:125-136](rust/src/turnkey/mod.rs))
- PrivySigner, FireblocksSigner, DfnsSigner, and CrossmintSigner must call `init()` before use; other signers are ready after construction
- AWS KMS and GCP KMS use official cloud SDKs with automatic credential discovery
- GCP KMS operates in PureEdDSA mode with `EC_SIGN_ED25519` algorithm
- The unified `Signer` enum uses conditional compilation extensively with `#[cfg(feature = "...")]`
