# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`solana-keychain` is a Rust library providing a unified interface for signing Solana transactions across multiple backend implementations. The architecture centers around a single `SolanaSigner` trait that abstracts over four different signing backends: Memory (local keypairs), Vault (HashiCorp), Privy, and Turnkey.

## Common Commands

### Build and Test
```bash
# Build the project (default features only - memory signer)
cargo build

# Build with all features
cargo build --all-features

# Run tests (requires all features for complete test coverage)
cargo test --all-features

# Run tests for a specific signer backend
cargo test --features memory
cargo test --features vault
cargo test --features privy
cargo test --features turnkey

# Run a single test
cargo test test_name --all-features
```

### Linting and Formatting
```bash
# Format and lint code (runs clippy with all warnings as errors)
make fmt

# Just format code
cargo fmt

# Just run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### Publishing a Release
```bash
# Prepare a new release (bumps version, generates CHANGELOG, creates tags)
make release

# After reviewing changes, push to GitHub
git push && git push --tags

# Then manually trigger the "Publish Rust Crate" workflow on GitHub Actions
# This will publish to crates.io and create a GitHub release
```

## Architecture

### Core Trait System

The library is built around the `SolanaSigner` trait ([src/traits.rs](src/traits.rs)) which defines the interface all signers must implement:
- `pubkey()` - Returns the signer's public key
- `sign_transaction()` - Signs a Solana transaction, modifying it in place
- `sign_message()` - Signs arbitrary bytes
- `is_available()` - Checks if the signer backend is healthy/reachable

### Unified Signer Enum

[src/lib.rs](src/lib.rs) provides a `Signer` enum that wraps all backend implementations, allowing runtime selection of signing backends while maintaining a single interface. Each variant corresponds to a feature-gated backend.

### Backend Implementations

All signers follow a consistent pattern but differ in where keys are stored:

1. **MemorySigner** ([src/memory/mod.rs](src/memory/mod.rs))
   - Stores keypair in memory
   - Supports multiple input formats: Base58, U8Array string, or JSON file path
   - Always available (no remote dependencies)
   - See [src/memory/keypair_util.rs](src/memory/keypair_util.rs) for key parsing logic

2. **VaultSigner** ([src/vault/mod.rs](src/vault/mod.rs))
   - Uses HashiCorp Vault's Transit engine for signing
   - Public key provided at construction (must match Vault key)
   - Uses `vaultrs` client library
   - Availability checked via key metadata read

3. **PrivySigner** ([src/privy/mod.rs](src/privy/mod.rs))
   - Requires `init()` call after construction to fetch public key
   - Uses Basic Auth with app_id:app_secret
   - RPC-style API with `signTransaction` method
   - Returns full signed transaction, extracts signature

4. **TurnkeySigner** ([src/turnkey/mod.rs](src/turnkey/mod.rs))
   - Uses P256 ECDSA signing for API authentication (X-Stamp header)
   - Signs raw payloads with hex encoding
   - Response contains r,s signature components that must be padded to 32 bytes each
   - Availability checked via `whoami` endpoint

### Error Handling

All errors are centralized in [src/error.rs](src/error.rs) using `thiserror`. The `SignerError` enum covers key formats, signing failures, remote API errors, serialization, and configuration issues.

### Feature Flags

The library uses Cargo features for zero-cost abstraction:
- `memory` (default) - Only includes MemorySigner
- `vault` - Adds VaultSigner with reqwest, vaultrs, base64
- `privy` - Adds PrivySigner with reqwest, base64
- `turnkey` - Adds TurnkeySigner with reqwest, base64, p256, hex, chrono
- `all` - Enables all backends

At least one feature must be enabled (enforced by `compile_error!` in lib.rs).

## Testing

Tests are co-located with implementation code in each module. Remote signers (Vault, Privy, Turnkey) use `wiremock` to mock HTTP endpoints, avoiding actual API calls during testing. Tests cover:
- Constructor validation (invalid keys, etc.)
- Successful signing operations
- Error cases (unauthorized, malformed responses)
- Availability checks

Run specific backend tests:
```bash
cargo test --features privy privy::tests
```

## Key Implementation Notes

- All signers serialize transactions with `bincode` before signing
- Privy and Turnkey use Base64 encoding for payloads/responses
- Vault uses Base64 for both input and output
- Turnkey requires special handling for signature component padding (see [src/turnkey/mod.rs:125-136](src/turnkey/mod.rs))
- PrivySigner must call `init()` before use; other signers are ready after construction
- The unified `Signer` enum uses conditional compilation extensively with `#[cfg(feature = "...")]`
