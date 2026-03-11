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
5. **All 5 match arms** in `impl SolanaSigner for Signer`:
   - `pubkey()`
   - `sign_transaction()`
   - `sign_message()`
   - `sign_partial_transaction()`
   - `is_available()`
6. Add feature to `compile_error!` cfg gate (search for `compile_error!`)

**c) `rust/src/error.rs`** — If signer uses reqwest, add feature to the `#[cfg(any(...))]` gate on `From<reqwest::Error> for SignerError`. Without this, `?` on reqwest calls won't compile.

### Critical Gotchas

- **5 trait methods**: Always read `rust/src/traits.rs` for the current trait definition — it is the source of truth.
- **Return type**: `sign_transaction` and `sign_partial_transaction` return `SignedTransaction = (String, Signature)` — a tuple of base64-encoded transaction + signature.
- **SDK adapter**: Import types from `crate::sdk_adapter`, not `solana_sdk` directly. The project supports both SDK v2 and v3 via an adapter layer.
- **`sign_partial_transaction`**: Serialize with `requireAllSignatures: false`. See existing signers (e.g., `rust/src/para/mod.rs`) for the pattern.

### Signer Patterns

**Sync constructor** (public key provided upfront): Memory, Vault, Turnkey, CDP
```
pub fn new(..., public_key: String) -> Result<Self, SignerError>
```

**Async init** (public key fetched from API): Privy, Fireblocks, Dfns, Para
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

**Async constructor** (no separate init step): AWS KMS, GCP KMS
```
pub async fn new(...) -> Result<Self, SignerError>  // single async constructor
```

**Config struct** (when many params): Fireblocks, Dfns
```
pub struct <Name>SignerConfig { ... }
pub fn new(config: <Name>SignerConfig) -> Self
```

## Step 3: Rust Tests

### Unit Tests (wiremock)
Add `#[cfg(test)] mod tests` at the bottom of `mod.rs`. Use `wiremock::MockServer` to mock HTTP endpoints. Cover:
- Constructor validation (valid + invalid inputs)
- `sign_message` success
- `sign_transaction` success
- Error cases (401, malformed response)
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

- `src/index.ts` — Add namespace export, factory function re-export, and class re-export
- `package.json` — Add `@solana/keychain-<name>: "workspace:*"` dependency
- `tsconfig.json` — Add `{ "path": "../<name>" }` reference

### Key TS Patterns

- Factory function `create<Name>Signer()` returns `SolanaSigner<TAddress>` (the interface)
- Class has `static async create()` method
- Private constructor
- Use `throwSignerError(SignerErrorCode.*, { cause, message })` from `@solana/keychain-core`
- Wrap all `fetch()` calls in try/catch

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
