---
name: add-signer
description: >
  Guide for adding a new signer backend to solana-keychain (Rust + TypeScript).
  Use when asked to "add a signer", "implement a signing backend", "integrate a
  key management service", "add X signer", "new signer backend", or when a
  contributor needs to add a new signing provider to the library.
---

# Add Signer Backend

Orchestrate adding a new signing backend to solana-keychain. Delegate to existing docs for code templates; this skill provides the procedure, file order, and gotchas.

## References

- **Code templates & checklists**: Read `docs/ADDING_SIGNERS.md`
- **CI workflow setup**: Use `/add-signer-ci` command
- **Most recent Rust signer**: `rust/src/para/` (use as pattern)
- **Most recent TS signer**: `typescript/packages/para/` (use as pattern)
- **Trait definition (source of truth)**: `rust/src/traits.rs`
- **Shared HTTP config**: `rust/src/http_client_config.rs`
- **Transaction utilities**: `rust/src/transaction_util.rs`
- **Unified TS factory**: `typescript/packages/keychain/src/create-keychain-signer.ts`
- **TS address resolver**: `typescript/packages/keychain/src/resolve-address.ts`
- **TS config union**: `typescript/packages/keychain/src/types.ts`

## Step 1: Gather Information

Ask the user for:
- Signer display name (e.g., "Para", "Dfns")
- Rust feature name / snake_case identifier (e.g., `para`, `dfns`)
- API documentation URL
- Authentication mechanism (API key, JWT, OAuth, etc.)

Determine from API docs:
- Does the signer need async `init()` to fetch the public key? (Most remote signers do)
- Does it use `reqwest` for HTTP calls? (Affects `error.rs` cfg gate)
- Config struct or individual constructor params?
- How are signatures returned? (base64, hex, raw bytes, r+s components)

## Step 2: Rust Implementation

Read `docs/ADDING_SIGNERS.md` for detailed code templates. Read `rust/src/para/mod.rs` as the most recent reference implementation.

### Files to Create

| File | When |
|------|------|
| `rust/src/<name>/mod.rs` | Always — signer struct + `SolanaSigner` impl + unit tests |
| `rust/src/<name>/types.rs` | If API needs custom request/response types |
| `rust/src/<name>/auth.rs` | If authentication is complex (e.g., challenge/response) |

### Files to Modify (in order)

**a) `rust/Cargo.toml`** — Add feature flag with `dep:` prefixed dependencies. Add feature to `all` list.

**b) `rust/src/lib.rs`** — 6 additions, all feature-gated with `#[cfg(feature = "<name>")]`:
1. Module declaration (`pub mod <name>`)
2. Re-export signer type (`pub use <name>::<Name>Signer`)
3. `Signer` enum variant
4. Factory method on `impl Signer` (`from_<name>`)
5. **All 4 match arms** in `impl SolanaSigner for Signer`:
   - `pubkey()`
   - `sign_transaction()`
   - `sign_message()`
   - `is_available()`
6. Add feature to `compile_error!` cfg gate (search for `compile_error!`)

**c) `rust/src/error.rs`** — If signer uses reqwest, add feature to the `#[cfg(any(...))]` gate on `From<reqwest::Error> for SignerError`. Without this, `?` on reqwest calls won't compile.

### Critical Gotchas

- **4 trait methods**: Always read `rust/src/traits.rs` for the current trait definition — it is the source of truth. The trait has `pubkey()`, `sign_transaction()`, `sign_message()`, and `is_available()`.
- **Return type**: `sign_transaction` returns `SignTransactionResult` (an enum of `Complete(SignedTransaction)` or `Partial(SignedTransaction)`). Use `TransactionUtil::classify_signed_transaction()` from `rust/src/transaction_util.rs` to classify the result.
- **Shared utilities**: Use `TransactionUtil::add_signature_to_transaction()` and `TransactionUtil::serialize_transaction()` instead of implementing your own.
- **SDK adapter**: Import types from `crate::sdk_adapter`, not `solana_sdk` directly. The project supports both SDK v2 and v3 via an adapter layer.
- **HTTPS enforcement**: Remote signers must use `reqwest::ClientBuilder::https_only(true)` gated behind `#[cfg(not(test))]` for wiremock compatibility.
- **HTTP timeouts**: Accept optional `HttpClientConfig` from `crate::http_client_config` for request/connect timeouts (defaults: 30s/5s).
- **Error safety**: Never use `.expect()` or `.unwrap()` on untrusted API responses. Both `Display` and `Debug` on `SignerError` are redacted — keep error messages generic.

### Signer Patterns

**Sync constructor** (public key provided upfront): Memory, Vault, Turnkey, CDP
```
pub fn new(..., public_key: String, http_config: Option<HttpClientConfig>) -> Result<Self, SignerError>
```

**Async init** (public key fetched from API): Privy, Fireblocks, Dfns, Para, Crossmint
```
pub fn new(...) -> Self  // or Result<Self, SignerError>
pub async fn init(&mut self) -> Result<(), SignerError>  // fetches pubkey
```
Factory in lib.rs calls `init()` automatically:
```rust
let mut signer = <Name>Signer::new(config);
signer.init().await?;
Ok(Self::<Name>(signer))
```
**Important**: Use `Option<Pubkey>` (not `Pubkey::default()`) for the public key field before `init()`. Return `SignerError::ConfigError` from signing methods if `init()` hasn't been called.

**Async constructor** (no separate init step): AWS KMS, GCP KMS
```
pub async fn new(...) -> Result<Self, SignerError>  // single async constructor
```

**Config struct** (when many params): Fireblocks, Dfns
```
pub struct <Name>SignerConfig { ... }
pub fn new(config: <Name>SignerConfig) -> Self
```

**HTTP client pattern** (all remote signers):
```rust
let http = http_config.unwrap_or_default();
let builder = reqwest::Client::builder()
    .timeout(http.resolved_request_timeout())
    .connect_timeout(http.resolved_connect_timeout());
#[cfg(not(test))]
let builder = builder.https_only(true);
let client = builder.build()?;
```

## Step 3: Rust Tests

### Unit Tests (wiremock)
Add `#[cfg(test)] mod tests` at the bottom of `mod.rs`. Use `wiremock::MockServer` to mock HTTP endpoints. Cover:
- Constructor validation (valid + invalid inputs)
- `sign_message` success
- `sign_transaction` success (verify `SignTransactionResult::Complete` vs `Partial`)
- Error cases (401, malformed response) — assert error type only, not error message text
- `is_available` success + failure

### Integration Tests
Create `rust/src/tests/test_<name>_integration.rs` with:
- `pub const` env var name declarations
- `async fn get_signer()` helper reading env vars via `dotenvy`
- Three test functions: `test_<name>_sign_message`, `test_<name>_sign_transaction`, `test_<name>_is_available`
- Feature gates: `#[cfg(feature = "<name>")]` inside the test file wrapping the test block, `#[cfg(feature = "integration-tests")]` on each test function

Register in `rust/src/tests/mod.rs` (no feature gate — the gate goes inside the file):
```rust
pub mod test_<name>_integration;
```

## Step 4: TypeScript Implementation

Read `docs/ADDING_SIGNERS.md` TypeScript section. Use `typescript/packages/para/` as template.

### Create Package: `typescript/packages/<name>/`

```
src/
├── index.ts                    — Public exports
├── <name>-signer.ts            — Factory function + class implementing SolanaSigner<TAddress>
├── types.ts                    — API types
└── __tests__/
    ├── <name>-signer.test.ts              — Unit tests (mocked fetch)
    ├── <name>-signer.integration.test.ts  — Integration tests
    └── setup.ts                           — Integration test config
```

Also create: `package.json`, `tsconfig.json`, `README.md`

### Update Umbrella Package: `typescript/packages/keychain/`

7 files to modify:
- `src/types.ts` — Add `YourSignerConfig` to `KeychainSignerConfig` discriminated union with `& { backend: '<name>' }`
- `src/create-keychain-signer.ts` — Add a switch case with a dynamic `await import('@solana/keychain-<name>')` (match the existing cases — no static import; the dispatcher must stay backend-free for tree-shaking)
- `src/resolve-address.ts` — Add to fast-path (if config has publicKey) or fetch-path (if async init) switch case
- `src/index.ts` — Add 4 export lines: config type, namespace, factory fn, deprecated class
- `package.json` — Add `@solana/keychain-<name>: "workspace:*"` dependency
- `tsconfig.json` — Add `{ "path": "../<name>" }` reference

The switch statements have exhaustive `never` checks — TypeScript will error if you add to the union but miss a case. The umbrella dispatch test tables and `resolve-address` test map are typed `satisfies Record<BackendName, …>`, so typecheck also fails until you add your backend there.

Also update `typescript/scripts/test-treeshake-umbrella.mjs`: add your package to `SIGNER_MARKERS` (two distinctive strings that appear in your built `dist/` — verify with grep) and your factory to `FACTORIES`. Without this, leakage of your backend into other bundles is undetectable.

### Key TS Patterns

- Factory function `create<Name>Signer()` returns `SolanaSigner<TAddress>` (the interface)
- Class has `static async create()` method
- Private constructor
- Use `throwSignerError(SignerErrorCode.*, { cause, message })` from `@solana/keychain-core`
- Remote API calls go through `fetchSignerJson()` from `@solana/keychain-core` — never call `fetch()` directly. It owns the error pipeline (HTTP_ERROR / REMOTE_API_ERROR + sanitization / PARSING_ERROR), redirect rejection, and a default 60s timeout
- Validate `apiBaseUrl` with `assertHttpsUrl(url, 'apiBaseUrl')` from core (returns the parsed URL); normalize first with `normalizeBaseUrl()` if the backend accepts trailing slashes
- Support `requestDelayMs`: validate with `validateRequestDelayMs()`, batch with `signBatchStaggered()` from core
- One-time crypto at construction: import/validate static key material (PEM parsing, `importPKCS8`, point decompression) once in `create()`/`init()` and store the result — only genuinely request-bound work (e.g. per-request JWT minting) belongs in the request path
- Validate provider-specific response shape after `fetchSignerJson()` with `?.` guards
- Add `@throws` JSDoc to factory functions listing error codes

## Step 5: Environment & Docs

- **`.env.example`** (root) — Add env vars with comment header identifying the signer
- **`typescript/packages/<name>/.env.example`** — Same env vars for TS integration tests
- **`README.md`** — Add row to supported backends table + usage example

## Step 6: CI Updates

Use the `/add-signer-ci` command for Phase 1 preparation (maintainer PR to `main`).

Phase 2 changes go in the contributor's signer PR:
- `ci.yml` — Add Rust feature to `backend` matrix + integration test to `test` matrix
- `typescript-ci.yml` — Add package to unit + integration test matrices
- `typescript-publish.yml` — Add package to `PUBLISH_PACKAGES`, GitHub Release array, summary table

## Step 7: Verify

```bash
# Rust
cd rust && cargo build --features <name>
cd rust && cargo test --features <name>
cd rust && cargo build --all-features
cd rust && cargo test --all-features
cd rust && cargo clippy --all-targets --all-features -- -D warnings
cd rust && cargo fmt --check

# TypeScript
pnpm --filter @solana/keychain-<name> test:unit
pnpm --filter @solana/keychain-<name> typecheck

# Or use just
just build
just test
just fmt
```
