# Common Errors When Adding a Signer

## Rust Compilation Errors

### `the trait bound 'SignerError: From<reqwest::Error>' is not satisfied`
**Cause:** Your signer uses `reqwest` but you didn't add its feature to the `#[cfg(any(...))]` gate in `error.rs`.
**Fix:** Add `feature = "<name>"` to the `#[cfg(any(...))]` on the `From<reqwest::Error> for SignerError` impl in `rust/src/error.rs`.

### `no variant named <Name> found for enum Signer`
**Cause:** Missing or mismatched `#[cfg(feature = "<name>")]` gate on the enum variant in `lib.rs`.
**Fix:** Ensure the feature name in `#[cfg(feature = "...")]` matches exactly what's in `Cargo.toml [features]`.

### `not all trait items implemented`
**Cause:** The `SolanaSigner` trait has 4 methods. Missing one of them.
**Fix:** Read `rust/src/traits.rs` for the current trait definition. Implement all 4 methods: `pubkey`, `sign_transaction`, `sign_message`, `is_available`.

### `unused import` or `dead_code` warnings with `cargo clippy`
**Cause:** Code that's only used behind a feature gate but not properly gated.
**Fix:** Add `#[cfg(feature = "<name>")]` to the import/code. All signer-specific code must be feature-gated.

### `compile_error!("At least one signer feature must be enabled")` fires unexpectedly
**Cause:** You forgot to add your feature to the `compile_error!` cfg gate in `lib.rs`.
**Fix:** Search for `compile_error!` in `rust/src/lib.rs` and add your feature to the `not(any(...))` list.

### `cannot find type 'Transaction' in this scope` or similar SDK type errors
**Cause:** Importing from `solana_sdk` directly instead of the adapter.
**Fix:** Import types from `crate::sdk_adapter`, not `solana_sdk`. The project supports multiple SDK versions via an adapter layer.

### Missing match arm in `impl SolanaSigner for Signer`
**Cause:** Added the enum variant but forgot to add the match arm in one or more trait method implementations.
**Fix:** There are 4 match blocks in `lib.rs` (one per trait method). Add your variant to ALL 4.

## Rust Test Errors

### `wiremock` mock not matching requests
**Cause:** Path or method mismatch between mock setup and actual HTTP call.
**Fix:** Check the exact path your signer calls (e.g., `/v1/sign` vs `/sign`). Use `Mock::given(any())` temporarily to debug what's being sent.

### Integration test hangs or times out
**Cause:** Missing or wrong env vars for the real API.
**Fix:** Check `.env.example` for required vars. Ensure `dotenvy::dotenv().ok()` is called at the start of the test.

## TypeScript Errors

### `Cannot find module '@solana/keychain-<name>'`
**Cause:** Package not linked in the workspace.
**Fix:** Run `pnpm install` from the repo root. Verify `pnpm-workspace.yaml` has `packages/*` glob under `typescript/`.

### `Property 'signMessages' is missing in type 'YourSigner'`
**Cause:** Incomplete `SolanaSigner<TAddress>` implementation.
**Fix:** Implement all required interface methods: `address`, `signMessages`, `signTransactions`, `isAvailable`.

### Integration test skipped unexpectedly
**Cause:** The `it.skipIf(!process.env.YOUR_VAR)` guard found the env var missing.
**Fix:** Create `typescript/packages/<name>/.env` with real credentials (not committed). Or run with env vars exported.

## Audit / Security Review Errors

### Raw remote error text in `SignerError` context
**Cause:** Passing `response.text()` directly into error messages. A malicious server could echo back tokens.
**Fix:** Use `sanitizeRemoteErrorResponse()` from `@solana/keychain-core` on all remote error text before including in error context.

### Bare `as TypeCast` on `.json()` result
**Cause:** Casting `await response.json()` directly to a type and accessing nested properties. A malformed response (`{}`) throws a raw `TypeError`.
**Fix:** Use optional chaining (`?.`) for shallow responses. For deeply nested responses, parse into `unknown` first, then validate shape with type guards. Throw `SIGNER_PARSING_ERROR` for unexpected shapes.

### `Buffer` or `node:crypto` usage in signer package
**Cause:** Using Node.js builtins that break in browsers and edge runtimes.
**Fix:** Replace `Buffer.from()` with `new TextEncoder().encode()`. Replace `node:crypto` with `@noble/curves` (ECDSA) or WebCrypto (`globalThis.crypto.subtle`). Use `@solana/codecs-strings` for base58/base64/hex encoding.

### Missing HTTPS enforcement on configurable URL
**Cause:** Signer accepts a `baseUrl`/`apiBaseUrl` config but doesn't validate the protocol.
**Fix:** Parse with `new URL(url)` and reject non-`https:` protocols with `SIGNER_CONFIG_ERROR`. Allow `http://localhost` only when `NODE_ENV=test`.

## CI Errors

### `Error: Process completed with exit code 101` on a feature you didn't touch
**Cause:** Adding your feature to `all` broke compilation of the combined feature set — likely a dependency conflict or duplicate type.
**Fix:** Run `cargo build --all-features` and `cargo test --all-features` locally before pushing.

### GitHub Actions can't find your integration test
**Cause:** Missing matrix entry in `ci.yml` or wrong test function name.
**Fix:** The `test` matrix in `ci.yml` must match the exact test function name pattern: `test_<name>_sign_message`, etc.
