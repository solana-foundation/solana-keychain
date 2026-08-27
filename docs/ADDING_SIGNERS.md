# Adding New Signers to solana-keychain

## Overview

This guide is for wallet service providers and developers who want to integrate new key management solutions into the `solana-keychain` library. By adding your signer implementation, you'll enable developers to use your service for secure Solana transaction signing through a unified interface.

We strongly prefer PRs that include the [Rust](#rust), [TypeScript](#typescript), and [Python](#python) implementations — the library maintains parity across all three. If you can only contribute one, that's fine, but expect the others to be required before the signer ships in a release.

> **Using Claude Code?** This repo includes an `add-signer-ci` skill (`.claude/skills/add-signer-ci/`) that wires up the CI workflows for a new signer contributed via a fork PR.

---

## Rust

### Architecture Overview

The library uses a trait-based architecture defined in [src/traits.rs](../rust/src/traits.rs): every signer implements the `SolanaSigner` base trait (`pubkey`, `sign_message`, `is_available`) plus exactly one capability trait matching the provider's shape — `TransactionSigner` (`sign_transaction`, caller broadcasts), `ModifyingSigner` (`modify_and_sign_transaction`, provider rewrites the transaction), or `SendingSigner` (`sign_and_send_transaction`, provider broadcasts). The library also provides a unified `Signer` enum that wraps all implementations, allowing runtime selection of signing backends while maintaining a consistent API.

### Quick Checklist

- [ ] Create your signer module with implementation
- [ ] Implement the `SolanaSigner` base trait plus the capability trait matching your provider's shape (usually `TransactionSigner`)
- [ ] Add a feature flag in `Cargo.toml`
- [ ] Update the `Signer` enum in `src/lib.rs` (variant, `dispatch_signer!` arm, `TransactionSigner` match arm)
- [ ] Update `src/error.rs` reqwest `From` impl cfg gate (if your signer uses reqwest)
- [ ] Enforce HTTPS and configure timeouts on HTTP clients
- [ ] Add comprehensive unit tests (wiremock-based, in your module)
- [ ] Add integration test file `rust/src/tests/test_<name>_integration.rs`
- [ ] Declare integration test module in `rust/src/tests/mod.rs`
- [ ] Update `.env.example` with all env vars (required + optional with defaults)
- [ ] Update documentation (README.md)
- [ ] CI workflow updates (coordinate with maintainers — see [CI Workflow Updates](#ci-workflow-updates-fork-prs))
- [ ] Submit PR

### Step 1: Create Your Signer Module

Create a new directory under `src/` for your implementation:

```bash
src/
├── your_service/
│   ├── mod.rs      # Main implementation with SolanaSigner trait
│   └── types.rs    # API request/response types (if needed)
```

### Step 2: Define Your Signer Struct

In `src/your_service/mod.rs`, define your signer struct:

```rust
//! YourService API signer integration

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignedTransaction;
use crate::{error::SignerError, traits::SolanaSigner};
use std::str::FromStr;

/// YourService-based signer using YourService's API
#[derive(Clone)]
pub struct YourServiceSigner {
    api_key: String,
    api_secret: String,
    wallet_id: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
}

impl std::fmt::Debug for YourServiceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YourServiceSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}
```

### Step 3: Implement Constructor and Helper Methods

Remote signers **must** enforce HTTPS and configure HTTP timeouts. Use the shared `HttpClientConfig` struct for timeout settings.

```rust
use crate::http_client_config::HttpClientConfig;

impl YourServiceSigner {
    /// Create a new YourServiceSigner
    pub fn new(
        api_key: String,
        api_secret: String,
        wallet_id: String,
        public_key: String,
        http_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        let http = http_config.unwrap_or_default();
        let builder = reqwest::Client::builder()
            .timeout(http.resolved_request_timeout())
            .connect_timeout(http.resolved_connect_timeout());

        // Enforce HTTPS in production; wiremock uses HTTP in tests
        #[cfg(not(test))]
        let builder = builder.https_only(true);

        let client = builder.build().map_err(|e| {
            SignerError::ConfigError(format!("Failed to build HTTP client: {e}"))
        })?;

        Ok(Self {
            api_key,
            api_secret,
            wallet_id,
            api_base_url: "https://api.yourservice.com/v1".to_string(),
            client,
            public_key: pubkey,
        })
    }

    /// Sign raw bytes using your service's API
    async fn sign(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // 1. Encode the message for your API (base64, hex, etc.)
        let encoded_message = base64::engine::general_purpose::STANDARD.encode(message);

        // 2. Build the API request
        let url = format!("{}/sign", self.api_base_url);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&serde_json::json!({
                "wallet_id": self.wallet_id,
                "message": encoded_message,
            }))
            .send()
            .await?;

        // 3. Check for errors — use generic messages, never expose raw API response text
        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(SignerError::RemoteApiError(format!(
                "YourService API returned status {status}"
            )));
        }

        // 4. Parse the response — always use map_err, never .expect() or .unwrap()
        let response_data: SignResponse = response
            .json()
            .await
            .map_err(|e| SignerError::SerializationError(format!("Failed to parse response: {e}")))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response_data.signature)
            .map_err(|e| SignerError::SerializationError(format!("Failed to decode signature: {e}")))?;

        // 5. Convert to Solana signature (must be exactly 64 bytes)
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SignerError::SigningFailed("Invalid signature length".to_string()))?;

        Ok(Signature::from(sig_array))
    }
}
```

### Step 4: Implement the Signer Traits

The `SolanaSigner` base trait has 2 async methods (`sign_message`, `is_available`) plus `pubkey()`; transaction signing goes in the capability trait — `TransactionSigner` for a provider that signs and leaves broadcasting to the caller. Note that `sign_transaction` returns `SignTransactionResult` — a tagged enum indicating whether the transaction is fully signed or partially signed.

Use the shared `TransactionUtil` helpers for signing and serialization instead of implementing your own.

```rust
use crate::transaction_util::TransactionUtil;
use crate::traits::{SignTransactionResult, TransactionSigner};

#[async_trait::async_trait]
impl SolanaSigner for YourServiceSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign(message).await
    }

    async fn is_available(&self) -> bool {
        // Implement a health check for your service
        // Example: ping endpoint or check credentials
        let url = format!("{}/health", self.api_base_url);
        self.client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl TransactionSigner for YourServiceSigner {
    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignTransactionResult, SignerError> {
        // 1. Serialize the transaction for your API
        let tx_bytes = bincode::serialize(tx)
            .map_err(|e| SignerError::SerializationError(format!("Failed to serialize: {e}")))?;

        // 2. Call your signing API
        let signature = self.sign(&tx_bytes).await?;

        // 3. Add the signature to the transaction at the correct position
        TransactionUtil::add_signature_to_transaction(tx, &self.public_key, signature)?;

        // 4. Serialize and classify as Complete or Partial
        let serialized = TransactionUtil::serialize_transaction(tx)?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            (serialized, signature),
        ))
    }
}
```

### Step 5: Add API Types (Optional)

If your API needs custom types, create `src/your_service/types.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SignRequest {
    pub wallet_id: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignResponse {
    pub signature: String,
}
```

### Step 6: Add Feature Flag

Update `Cargo.toml` to add your signer as an optional feature:

```toml
[features]
default = ["memory"]
memory = []
vault = ["dep:reqwest", "dep:vaultrs", "dep:base64"]
privy = ["dep:reqwest", "dep:base64"]
turnkey = ["dep:reqwest", "dep:base64", "dep:p256", "dep:hex", "dep:chrono"]
your_service = ["dep:reqwest", "dep:base64"]  # Add your feature
all = ["memory", "vault", "privy", "turnkey", "your_service"]  # Update all

[dependencies]
# Add any specific dependencies your signer needs under the optional section
# If they're already in the deps, just reference them in the feature
```

### Step 7: Update the Signer Enum

Add your signer to `src/lib.rs`. The base `SolanaSigner` impl dispatches through the `dispatch_signer!` macro, so add one arm there; capability access lives in the explicit `as_transaction_signer()` / `as_sending_signer()` matches, so add your arm to each (a `Some(s)` arm in the accessor matching your capability trait, and for `as_transaction_signer` a `None` arm if your backend is sending-only).

```rust
// Add feature-gated module
#[cfg(feature = "your_service")]
pub mod your_service;

// Re-export your signer type
#[cfg(feature = "your_service")]
pub use your_service::YourServiceSigner;

// Add to Signer enum
#[derive(Debug)]
pub enum Signer {
    #[cfg(feature = "memory")]
    Memory(MemorySigner),

    // ... existing variants

    #[cfg(feature = "your_service")]
    YourService(YourServiceSigner),  // Add your variant
}

// Add constructor method
impl Signer {
    /// Create a YourService signer
    #[cfg(feature = "your_service")]
    pub fn from_your_service(
        api_key: String,
        api_secret: String,
        wallet_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        Ok(Self::YourService(YourServiceSigner::new(
            api_key,
            api_secret,
            wallet_id,
            public_key,
            None, // uses default HttpClientConfig
        )?))
    }
}

// Update the dispatch macro — the base SolanaSigner impl uses it for
// pubkey, sign_message and is_available
macro_rules! dispatch_signer {
    ($self:ident, $signer:pat => $body:expr) => {
        match $self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService($signer) => $body,
        }
    };
}

// Add your arm to the capability accessors
impl Signer {
    pub fn as_transaction_signer(&self) -> Option<&dyn TransactionSigner> {
        match self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService(s) => Some(s),
        }
    }
}
```

### Step 8: Add Comprehensive Tests

Add tests to your module (at the bottom of `src/your_service/mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{signature::Keypair, signer::Signer};
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_new() {
        let keypair = Keypair::new();
        let signer = YourServiceSigner::new(
            "test-key".to_string(),
            "test-secret".to_string(),
            "test-wallet".to_string(),
            keypair.pubkey().to_string(),
            None,
        );
        assert!(signer.is_ok());
    }

    #[tokio::test]
    async fn test_sign_message() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let message = b"test message";
        let signature = keypair.sign_message(message);

        // Mock the signing endpoint
        Mock::given(method("POST"))
            .and(path("/sign"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = YourServiceSigner::new(
            "test-key".to_string(),
            "test-secret".to_string(),
            "test-wallet".to_string(),
            keypair.pubkey().to_string(),
            None,
        ).unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();

        Mock::given(method("POST"))
            .and(path("/sign"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = YourServiceSigner::new(
            "bad-key".to_string(),
            "bad-secret".to_string(),
            "test-wallet".to_string(),
            keypair.pubkey().to_string(),
            None,
        ).unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
    }
}
```

### Step 9: Update `error.rs` Reqwest Cfg Gate

If your signer uses `reqwest`, you must add your feature to the `#[cfg(any(...))]` gate on the `From<reqwest::Error>` impl in `rust/src/error.rs`:

```rust
#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "your_service"  // Add your feature here
))]
impl From<reqwest::Error> for SignerError {
    fn from(err: reqwest::Error) -> Self {
        SignerError::HttpError(err.to_string())
    }
}
```

Without this, `?` on reqwest calls won't compile when only your feature is enabled.

### Step 10: Add Integration Tests

Create `rust/src/tests/test_<name>_integration.rs`. Integration tests run against the real service API (not wiremock) and are gated behind `#[cfg(feature = "integration-tests")]`. Each file needs:

- `pub const` declarations for env var names
- A `get_signer()` helper that reads env vars via `dotenvy`
- Three test functions: `test_<name>_sign_message`, `test_<name>_sign_transaction`, `test_<name>_is_available`
- Feature gates: `#[cfg(feature = "your_service")]` on the module, `#[cfg(feature = "integration-tests")]` on each test

See [rust/src/tests/test_para_integration.rs](../rust/src/tests/test_para_integration.rs) for a complete reference.

Add your integration test module to `rust/src/tests/mod.rs`:

```rust
pub mod test_your_service_integration;
```

### Step 11: Update Environment Variables

Update the root `.env.example` with your signer's env vars, following the existing pattern:

```bash
# YourService Configuration (for SIGNER_TYPE=your_service)
YOUR_SERVICE_API_KEY=your-api-key
YOUR_SERVICE_WALLET_ID=your-wallet-id
# YOUR_SERVICE_API_BASE_URL=https://api.yourservice.com/v1  # Optional, defaults to this
```

Rules:
- Add a comment header identifying the signer
- List required vars first (uncommented, with placeholder values)
- List optional vars commented out with their defaults
- If your signer has a configurable base URL, include it as optional
- All env vars used in integration tests must appear in `.env.example`

### Step 12: Update Documentation

#### Update README.md

Add your signer to the supported backends table:

```markdown
| Backend | Use Case | Feature Flag |
|---------|----------|--------------|
| **Memory** | Local keypairs, development, testing | `memory` (default) |
| **Vault** | Enterprise key management with HashiCorp Vault | `vault` |
| **Privy** | Embedded wallets with Privy infrastructure | `privy` |
| **Turnkey** | Non-custodial key management via Turnkey | `turnkey` |
| **YourService** | [Brief description of your service] | `your_service` |
```

Add usage example:

```markdown
### YourService

\```rust
use solana_keychain::{Signer, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Signer::from_your_service(
        "your-api-key".to_string(),
        "your-api-secret".to_string(),
        "your-wallet-id".to_string(),
        "your-public-key".to_string(),
    )?;

    let pubkey = signer.pubkey();
    println!("Public key: {}", pubkey);

    Ok(())
}
\```
```

### CI Workflow Updates (Fork PRs)

CI is a two-phase process. Coordinate with maintainers to prepare `main` before your PR can be tested — they'll update `fork-external-live-manual.yml`, add env vars to `ci.yml`, and configure GitHub Secrets.

**Your PR must include** these Phase 2 CI changes alongside your signer code:

- **`ci.yml`**: add your Rust feature to the `backend` matrix (before `all`) + your integration test function to the `test` matrix
- **`typescript-ci.yml`**: add your package to the unit + integration test matrices, and add env vars to the integration test step
- **`typescript-publish.yml`**: add your package to `PUBLISH_PACKAGES`, GitHub Release `packages` array, and the summary table

---

## TypeScript

### Quick Checklist

- [ ] Create package `typescript/packages/<name>/`
- [ ] Implement the `SolanaTransactionSigner` and `SolanaMessageSigner` interfaces from `@solana/keychain-core`
- [ ] Export `createXSigner()` factory function returning `SolanaTransactionSigner<TAddress> & SolanaMessageSigner<TAddress>`
- [ ] Keep the signer class internal — do not export it from `index.ts`
- [ ] Export config interface (`XSignerConfig`)
- [ ] Enforce HTTPS on `apiBaseUrl` config fields
- [ ] Sanitize remote API error text with `sanitizeRemoteErrorResponse()`
- [ ] Unit tests with vitest + mocks
- [ ] Integration tests using `runSignerIntegrationTest` + `setup.ts`
- [ ] Update umbrella package `typescript/packages/keychain/` (see [Umbrella Package](#umbrella-package) — 7 files)
- [ ] Honor `config?.abortSignal` in every signing method (thread it into `fetchSignerJson` and `signBatchStaggered`)
- [ ] Add your backend to the capability matrix in `typescript/README.md` ("Signer capabilities")
- [ ] README with `createXSigner()` as primary usage
- [ ] `.env.example` with required env vars
- [ ] CI updates (`typescript-ci.yml`, `typescript-publish.yml`)

### Package Structure

```
typescript/packages/<name>/
├── package.json
├── tsconfig.json
├── README.md
└── src/
    ├── index.ts                    # Public exports
    ├── <name>-signer.ts            # Signer class + factory function
    ├── types.ts                    # API request/response types
    └── __tests__/
        ├── <name>-signer.test.ts              # Unit tests (mocked)
        ├── <name>-signer.integration.test.ts  # Integration tests
        └── setup.ts                           # Integration test config
```

See [`typescript/packages/para/`](../typescript/packages/para/) for a complete reference.

### Signer Implementation

`@solana/keychain-core` defines one capability interface per Kit signer shape, mirroring the Rust capability traits: `SolanaTransactionSigner` (Rust `TransactionSigner`), `SolanaModifyingSigner` (Rust `ModifyingSigner`), `SolanaSendingSigner` (Rust `SendingSigner`), and the orthogonal `SolanaMessageSigner` (Rust's base-trait `sign_message`). `SolanaSigner` is the union of the three transaction shapes.

A typical signer implements `SolanaTransactionSigner<TAddress>` and `SolanaMessageSigner<TAddress>` (a class lists both interfaces; it cannot implement the intersection type). Together they require:

- `readonly address: Address<TAddress>`
- `signMessages(messages, config?): Promise<readonly SignatureDictionary[]>`
- `signTransactions(transactions, config?): Promise<readonly SignatureDictionary[]>`
- `isAvailable(): Promise<boolean>` — health check for the signing backend

If your backend has no message-sign endpoint, skip `SolanaMessageSigner` and expose no `signMessages` method at all (see Utila) — Kit classifies signers by duck-typed method presence, so a present-but-throwing method would misroute.

The `config` parameter is Kit's optional partial-signer config. Every signing method must honor `config?.abortSignal` — see the abort-support rule under [Key rules](#factory-function--class).

#### Config Interface

Define your config interface in the signer file alongside the class. The config shape depends on whether your signer fetches the public key during initialization:

```typescript
// Async signer — public key fetched during create()
export interface YourSignerConfig {
    apiKey: string;
    walletId: string;
    apiBaseUrl?: string;
    requestDelayMs?: number;
}

// Sync signer — public key provided upfront
export interface YourSignerConfig {
    keyId: string;
    publicKey: string;   // base58-encoded Solana address
    requestDelayMs?: number;
}
```

#### Factory Function + Class

The factory function is the only public API. It returns `SolanaTransactionSigner<TAddress> & SolanaMessageSigner<TAddress>` (the capability interfaces), not the concrete class — the class itself is never exported from `index.ts`, so it stays reachable only through the factory (mirror `@solana/keychain-crossmint` for this pattern). Place the factory above the class definition, after imports.

**Async signer** (fetches public key during init — most common):

```typescript
import {
    SolanaMessageSigner,
    SolanaTransactionSigner,
    SignerErrorCode,
    throwSignerError,
} from '@solana/keychain-core';

export async function createYourSigner<TAddress extends string = string>(
    config: YourSignerConfig,
): Promise<SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress>> {
    return await YourSigner.create(config);
}

class YourSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;

    static async create<TAddress extends string = string>(
        config: YourSignerConfig,
    ): Promise<YourSigner<TAddress>> {
        if (!config.apiKey || !config.walletId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required configuration fields',
            });
        }
        const address = await fetchPublicKey<TAddress>(config);
        return new YourSigner<TAddress>(config, address);
    }

    private constructor(config: YourSignerConfig, address: Address<TAddress>) {
        this.address = address;
        // ...
    }

    // ... implement signMessages, signTransactions, isAvailable
}
```

**Sync signer** (public key provided in config):

```typescript
export function createYourSigner<TAddress extends string = string>(
    config: YourSignerConfig,
): SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress> {
    return new YourSigner<TAddress>(config);
}

class YourSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;

    constructor(config: YourSignerConfig) {
        // validate config, set this.address from config.publicKey
    }

    // ... implement signMessages, signTransactions, isAvailable
}
```

**Key rules:**

- **HTTPS enforcement**: If your signer accepts an `apiBaseUrl` config field, validate it in `create()` with `assertHttpsUrl()` from `@solana/keychain-core`:
  ```typescript
  import { assertHttpsUrl } from '@solana/keychain-core';

  assertHttpsUrl(apiBaseUrl, 'apiBaseUrl'); // returns the parsed URL if you need host/origin
  ```
- **Remote API calls**: use `fetchSignerJson()` from `@solana/keychain-core` instead of calling `fetch()` directly. It owns the whole error pipeline — network failure → `HTTP_ERROR`, non-2xx → `REMOTE_API_ERROR` with the response body sanitized via `sanitizeRemoteErrorResponse()`, bad JSON → `PARSING_ERROR` — plus redirect rejection and a default 60s timeout:
  ```typescript
  import { fetchSignerJson } from '@solana/keychain-core';

  const data = await fetchSignerJson<YourApiResponse>({
      init: { body: JSON.stringify(request), headers, method: 'POST' },
      providerName: 'YourService',
      url,
  });
  const signature = data?.result?.signature;
  if (!signature) {
      throwSignerError(SignerErrorCode.SIGNING_FAILED, { ... });
  }
  ```
  Validate provider-specific response shape (with optional chaining) after the call.
- **Batch staggering**: support the `requestDelayMs` config field for rate-limited APIs. Validate it with `validateRequestDelayMs()` and implement `signMessages`/`signTransactions` with `signBatchStaggered()` from `@solana/keychain-core` (see any existing signer).
- **Abort support**: thread `config?.abortSignal` from every signing method into `fetchSignerJson({ abortSignal, ... })` and `signBatchStaggered(items, fn, delayMs, config?.abortSignal)`. `fetchSignerJson` composes the signal with its timeout and rethrows the caller's abort reason unwrapped, so cancellation stays distinguishable from failure — never catch and rewrap it as a signer error.
- **One-time crypto at construction**: import/validate static key material (PEM parsing, `importPKCS8`, point decompression) once in `create()`/`init()` and store the imported key — only genuinely request-bound work (e.g. minting a per-request JWT) belongs in the request path.
- Add `cause` to catch blocks to preserve stack traces
- Add `@throws` JSDoc to factory functions listing the error codes they can throw

#### Index Exports

```typescript
// index.ts
export { createYourSigner } from './your-signer.js';
export type { YourSignerConfig } from './your-signer.js';
export type { YourApiResponse, YourApiRequest } from './types.js';
```

### Unit Tests

Use vitest with mocked `fetch`. Test:

- `create()` with valid config
- Config validation errors (missing fields, invalid public key)
- `signMessages` success + error paths
- `signTransactions` success + error paths
- `isAvailable` success + failure
- Network errors (`fetch` throws — `HTTP_ERROR` code)
- `requestDelayMs` validation and behavior
- Abort: an already-aborted `config.abortSignal` rejects with the abort reason (not a `SignerError`) without issuing a request

Run your package's tests during development:

```bash
pnpm --filter @solana/keychain-<name> test:unit
```

See any existing `*-signer.test.ts` for the pattern.

### Integration Tests

All integration tests use the shared test runner from `@solana/keychain-test-utils`.

#### setup.ts

```typescript
import type { SolanaSigner } from '@solana/keychain-core';
import type { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createYourSigner } from '../your-signer.js';

const SIGNER_TYPE = 'your-signer';
const REQUIRED_ENV_VARS = ['YOUR_API_KEY', 'YOUR_WALLET_ID'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createYourSigner({
            apiKey: process.env.YOUR_API_KEY!,
            walletId: process.env.YOUR_WALLET_ID!,
            apiBaseUrl: process.env.YOUR_API_BASE_URL,
        }),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
```

**Important:** The `createSigner` field must use the `createXSigner()` factory function, not the class directly. For sync factories, wrap in `Promise.resolve()`.

#### Integration Test File

```typescript
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import { config } from 'dotenv';
import { describe, it } from 'vitest';
import { getConfig } from './setup.js';

config();

describe('YourSigner Integration', () => {
    it.skipIf(!process.env.YOUR_API_KEY)('signs transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signTransaction']));
    });
    it.skipIf(!process.env.YOUR_API_KEY)('signs messages with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['signMessage']));
    });
    it.skipIf(!process.env.YOUR_API_KEY)('simulates transactions with real API', async () => {
        await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
    });
});
```

### Umbrella Package

Update `typescript/packages/keychain/` to register your signer in the unified factory. There are 7 files to modify:

**a) `keychain/src/types.ts`** — add your config to the discriminated union:

```typescript
import type { YourSignerConfig } from '@solana/keychain-your-signer';

export type KeychainSignerConfig =
    // ... existing members
    | (YourSignerConfig & { backend: 'your-signer' });
```

**b) `keychain/src/create-keychain-signer.ts`** — add import and switch case:

```typescript
import { createYourSigner } from '@solana/keychain-your-signer';

// Inside the switch:
case 'your-signer':
    return await createYourSigner(stripBackend(config));
```

**c) `keychain/src/resolve-address.ts`** — add to the correct path:

If your signer config includes the public key (sync), add to the fast-path group:
```typescript
case 'your-signer':
    assertIsAddress(config.publicKey);
    return config.publicKey;
```

If your signer fetches the public key from an API (async), add to the fetch group:
```typescript
case 'your-signer':
// (falls through to createKeychainSigner call)
```

**d) `keychain/src/index.ts`** — add 3 export lines across the tiers:

```typescript
// Individual config type (flat re-export)
export type { YourSignerConfig } from '@solana/keychain-your-signer';

// Namespaced signer implementation
export * as yourSigner from '@solana/keychain-your-signer';

// Factory function (preferred API)
export { createYourSigner } from '@solana/keychain-your-signer';
```

**e) `keychain/package.json`** — add to `dependencies`:

```json
"@solana/keychain-your-signer": "workspace:*"
```

**f) `keychain/tsconfig.json`** — add to `references`:

```json
{ "path": "../your-signer" }
```

> **Note:** The `createSigner()` and `resolveAddress()` switch statements have exhaustive `never` checks — TypeScript will emit a compile error if you add your config to the union but forget to handle it in the switch. The umbrella test tables are typed `satisfies Record<BackendName, …>`, so typecheck also fails until your backend is covered there.

**g) `typescript/scripts/test-treeshake-umbrella.mjs`** — add your package to `SIGNER_MARKERS` (two distinctive strings that appear in your built `dist/` output — verify with grep before picking them) and your factory to the `FACTORIES` list. Without this, your backend leaking into other factories' bundles goes undetected.

**h) Managed-broadcast (sending-signer) backends only** — if your backend rewrites the transaction message and/or broadcasts server-side, its signature cannot be applied to the caller's transaction, so it must be a `SolanaSendingSigner` (see `@solana/keychain-core`) instead of a `SolanaTransactionSigner`. That changes the checklist:

- The signer class implements `signAndSendTransactions()` and exposes **no** `signTransactions` (nor `signMessages`, unless the backend genuinely signs messages) — Kit classifies signers by duck-typed method presence, so throwing methods are not enough. See Crossmint, or Fordefi's own-property pattern for a package serving both shapes.
- `signAndSendTransactions(transactions, config?)` takes Kit's sending-signer config and must honor `config?.abortSignal` like every other signing method. A correctly shaped sending signer is picked up automatically by core's `signAndSendTransaction()` helper and reported by `signerCapabilities()` — no extra registration needed.
- Add a typed `createKeychainSigner` overload in `keychain/src/create-keychain-signer.ts` returning your sending-signer type (Crossmint and Fordefi-native have precedents), in addition to the switch case.
- Add your backend to the exclusions in `KeychainKitPluginConfig` (`typescript/packages/kit-plugin/src/keychain-plugin.ts`) — sending signers cannot serve as a Kit client `payer`/`identity` — and mention it in the kit-plugin README.
- Assert the guard directions in unit tests: `isTransactionPartialSigner()` false and `isTransactionSendingSigner()` true for your instances.

### README

Show `createXSigner()` as the primary usage pattern in all examples:

```typescript
import { createYourSigner } from '@solana/keychain-your-signer';

const signer = await createYourSigner({
    apiKey: 'your-api-key',
    walletId: 'your-wallet-id',
});
```

### package.json

Copy `packages/para/package.json` as a starting point and modify. Key fields:

```json
{
    "name": "@solana/keychain-<name>",
    "author": "Solana Foundation",
    "version": "1.0.1",
    "description": "Your signer for Solana transactions",
    "license": "MIT",
    "repository": "https://github.com/solana-foundation/solana-keychain",
    "type": "module",
    "sideEffects": false,
    "main": "./dist/index.js",
    "types": "./dist/index.d.ts",
    "exports": {
        ".": {
            "types": "./dist/index.d.ts",
            "import": "./dist/index.js"
        }
    },
    "files": ["dist", "src"],
    "scripts": {
        "build": "tsc --build",
        "clean": "rm -rf dist *.tsbuildinfo",
        "prepack": "pnpm run build",
        "test": "vitest run",
        "test:unit": "vitest run --config ../../vitest.config.unit.ts",
        "test:integration": "vitest run --config ../../vitest.config.integration.ts",
        "typecheck": "tsc --noEmit"
    },
    "dependencies": {
        "@solana/keychain-core": "workspace:*",
        "@solana/addresses": "^6.0.1",
        "@solana/codecs-strings": "^6.0.1",
        "@solana/keys": "^6.0.1",
        "@solana/signers": "^6.0.1",
        "@solana/transactions": "^6.0.1"
    },
    "devDependencies": {
        "@solana/keychain-test-utils": "workspace:*",
        "dotenv": "^17.2.3"
    },
    "publishConfig": {
        "access": "public"
    }
}
```

### tsconfig.json

```json
{
    "extends": "../../tsconfig.base.json",
    "compilerOptions": {
        "outDir": "./dist",
        "rootDir": "./src",
        "composite": true
    },
    "include": ["src/**/*"],
    "exclude": ["node_modules", "dist"],
    "references": [{ "path": "../core" }]
}
```

New packages are auto-discovered by `pnpm-workspace.yaml` (glob: `packages/*`).

### CI Updates

Your PR must include:

- **`typescript-ci.yml`**: add package to unit + integration test matrices, add env vars to integration test step
- **`typescript-publish.yml`**: add package to `PUBLISH_PACKAGES`, GitHub Release `packages` array, and summary table

## Python

### Quick Checklist

- [ ] Create module `python/src/solana_keychain/<name>/`
- [ ] Subclass `SolanaSigner` from `solana_keychain.core` plus the capability class matching your provider's shape (usually `TransactionSigner`)
- [ ] Export `async create_x_signer()` factory (awaits `init()` when the backend needs it)
- [ ] Export a config dataclass (`XSignerConfig`) with secrets marked `field(repr=False)`
- [ ] Enforce HTTPS on base-URL fields with `assert_https_url()`
- [ ] Route every request through `fetch_signer_json()` so the error pipeline and sanitization apply
- [ ] Add the backend to `_BACKENDS` in `python/src/solana_keychain/keychain.py`
- [ ] Guard provider-SDK imports and declare an optional extra in `pyproject.toml`
- [ ] Unit tests with pytest — `respx` for HTTP backends, stub clients for SDK backends
- [ ] Integration test factory in `python/tests/integration/test_live_signers.py`
- [ ] README backends table + install-extras line
- [ ] `.env.example` with required env vars
- [ ] CI updates (`python-ci.yml` signer gating and integration matrix)

### Module Structure

```
python/src/solana_keychain/<name>/
├── __init__.py          # Public exports
├── signer.py            # Signer class + config dataclass + factory
└── jwt.py / auth.py     # Auth helpers, when the provider needs them
```

Tests live at `python/tests/test_<name>_signer.py`. See
[`python/src/solana_keychain/para/`](../python/src/solana_keychain/para/) for a
pure-HTTP reference and
[`python/src/solana_keychain/aws_kms/`](../python/src/solana_keychain/aws_kms/)
for an extras-gated SDK reference.

### Signer Implementation

Subclass `SolanaSigner` and implement the three base members:

- `pubkey` property returning `solders.pubkey.Pubkey`
- `async sign_message(message: bytes) -> Signature`
- `async is_available() -> bool`

Transaction handling goes in the capability class you also subclass, and a
backend subclasses exactly one: `TransactionSigner`
(`async sign_transaction(transaction) -> SignedTransaction`, the caller
broadcasts), `ModifyingSigner`
(`async modify_and_sign_transaction(transaction) -> SignedTransaction`, the
provider rewrites the transaction) or `SendingSigner`
(`async sign_and_send_transaction(transaction) -> Signature`, the provider
broadcasts). A backend never defines an entry point it cannot serve.

Backends that must resolve an address remotely add `async init()` and raise
`SIGNER_NOT_INITIALIZED` from a private `_initialized_pubkey()` helper when used
before initialization; the factory awaits `init()` so callers never see an
uninitialized signer.

Always verify the signature the provider returns against the resolved public key
before handing it back. For providers that rewrite the transaction before signing,
verify against the bytes they signed — and use
`solana_keychain.core.signed_message_bytes()`, which adds the `0x80` prefix that
versioned-message signatures cover.

### Optional Extras

Backends needing a provider SDK must not break the base install. Guard the import
and name the extra in the error:

```python
try:
    import provider_sdk
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.<name> requires the <name> extra: "
        "pip install 'solana-keychain[<name>]'"
    ) from error
```

Declare it under `[project.optional-dependencies]` in `python/pyproject.toml`,
add the same packages to the `dev` extra so CI exercises them, and leave the
backend out of the package root's eager exports.

### Testing

Unit tests must not touch the network: mock HTTP with `respx`, and inject stub
clients for SDK-based backends (`botocore.stub.Stubber` for AWS, a hand-written
async stub for GCP). Cover at minimum the success path with request assertions,
each provider-specific error path, signature-verification failure, and that no
secret appears in `str()`/`repr()`/`args` of raised errors.

Integration tests are env-gated: add a `make_<name>_signer()` factory to
`python/tests/integration/test_live_signers.py` using the same environment
variable names as the Rust and TypeScript suites, and register it in
`_MESSAGE_CAPABLE` (or `_TRANSACTION_ONLY` for backends without `sign_message`).

### CI Updates

- **`python-ci.yml`**: add the backend to the `CI_SIGNER_*` gating in
  `resolve-signers` and to the integration matrix
- **`python-publish.yml`**: no change needed — the package publishes as a whole

---

## Submission Checklist

Before submitting your PR:

- [ ] Code compiles without warnings (`just build`)
- [ ] All tests pass (`just test`)
- [ ] Code is formatted/linting passes (`just fmt`)
- [ ] No hardcoded values or secrets in code
- [ ] Error messages use generic text (no raw API response data)
- [ ] No `.expect()` or `.unwrap()` on untrusted API responses
- [ ] HTTPS enforced on HTTP clients (Rust: `https_only(true)`, TS: URL protocol check)
- [ ] HTTP timeouts configured via `HttpClientConfig`
- [ ] Follows naming conventions (snake_case for Rust and Python, camelCase for TypeScript)
- [ ] `error.rs` reqwest cfg gate updated (if using reqwest)
- [ ] Integration test file added with standard test scenarios
- [ ] `.env.example` updated (root + TS package)
- [ ] Added to README.md supported backends table
- [ ] CI changes included
- [ ] TypeScript package with unit + integration tests
- [ ] Python module with unit + integration tests, registered in the umbrella `_BACKENDS`
- [ ] Python optional extra declared (if the backend needs a provider SDK)
- [ ] Umbrella package updated (7 files — see [Umbrella Package](#umbrella-package))
- [ ] Coordinated with maintainers on Phase 1 CI preparation

## Implementation Tips

### Error Handling

Always use the existing error types. Both `Display` and `Debug` on `SignerError` are redacted — the inner string is only accessible programmatically, never printed in logs. Keep error messages generic and avoid including raw API response data:

```rust
// Good — generic message, no raw API data
return Err(SignerError::RemoteApiError(format!(
    "YourService API returned status {status}"
)));

// Good — converts from standard errors with map_err
let bytes = base64::decode(data)
    .map_err(|e| SignerError::SerializationError(format!("Failed to decode: {e}")))?;

// BAD — never use .expect() on untrusted data
let decoded = STANDARD.decode(&api_response.signature).expect("decode failed");

// BAD — never include raw API error text
return Err(SignerError::RemoteApiError(format!("API error: {error_body}")));
```

### Security Requirements

These are not suggestions. Consumers pick a backend on the strength of them, so
a new backend that skips one silently breaks what the rest of the library
guarantees. If your provider makes one impossible, say so in the PR and in
[SECURITY_MODEL.md](SECURITY_MODEL.md).

- **Verify what the provider signed.** Compute the message bytes locally, and
  verify the returned signature against them before attaching it. If the
  provider returns a whole signed transaction, deserialize it, take the signature
  at your signer's required-signer position, and verify that. A signature that
  does not verify must fail, never be attached.
- **Declare whether the provider broadcasts.** If it executes server-side,
  implement the sending shape (`SendingSigner` in Rust,
  `SolanaSendingSigner` in TypeScript, `core.SendingSigner` in Go) and
  return the signature that identifies the landed transaction. If the provider
  has no sign-only endpoint at all, make the backend sending-only: fail the
  sign-only entry point rather than submitting behind the caller's back.
- **Never leave the caller holding a transaction the signature does not cover.**
  A provider that rewrites the transaction produces a signature over its own
  bytes. Either leave the caller's transaction untouched because there is nothing
  for them to broadcast (the broadcast-managed case), or take the modifying shape
  (`ModifyingSigner` in Rust) and replace it wholesale with the provider's bytes,
  so that what the caller holds is what was signed. Never merge the signature
  into the caller's original.
- **Report broadcast uncertainty as such.** A failure after submission may still
  have landed. Surface `BROADCAST_UNCONFIRMED` rather than a generic error a
  caller might blindly retry into a duplicate spend, and carry the provider
  transaction id whenever you have one. If the create itself failed there is no
  id to carry, so send a message-derived idempotency key on every create: that
  is what makes a byte-identical resend safe.
- **Never sign before init.** Hold the public key as an optional value and fail
  with a config error if signing is attempted first; never fall back to the zero
  address.
- **Never log sensitive data** (private keys, API secrets, raw API responses)
- **Use `Debug` impl that hides sensitive fields** — both `Debug` and `Display` on `SignerError` are redacted by default; do not rely on error messages containing details
- **Validate all inputs** (public keys, signatures)
- **Enforce HTTPS** — use `reqwest::ClientBuilder::https_only(true)` (Rust) or validate URL protocol (TypeScript); gate with `#[cfg(not(test))]` for wiremock compatibility
- **Configure HTTP timeouts** — use `HttpClientConfig` for request/connect timeouts (defaults: 30s/5s)
- **Never use `.expect()` or `.unwrap()` on untrusted API responses** — always use `map_err` to convert to `SignerError`
- **Sanitize remote error text** — in TypeScript, use `sanitizeRemoteErrorResponse()` before including API error text in errors
- **Use `Option<Pubkey>` for async-init signers** — do not default to `Pubkey::default()` (the zero address); return `SignerError::ConfigError` if signing is attempted before init
- **Zeroize intermediate key material** — use `zeroize::Zeroizing<Vec<u8>>` for buffers containing raw private key bytes
- Consider rate limiting and retry logic

### Testing with Mocks

Use `wiremock` for Rust and mocked `fetch` for TypeScript:

```rust
#[cfg(test)]
mod tests {
    use wiremock::{MockServer, Mock, ResponseTemplate};

    #[tokio::test]
    async fn test_api_call() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Use mock_server.uri() as your api_base_url
    }
}
```

## Example PR Structure

```
feat(signer): add YourService signer integration

Adds support for YourService as a signing backend. [Link to YourService Documentation](https://yourservice.com/docs)


- [X] Code compiles without warnings (`just build`)
- [X] Code is formatted/linting passes (`just fmt`)
- [X] Add comprehensive tests with wiremock - All tests pass (`just test`)
- [X] Implemented SolanaSigner trait for YourServiceSigner
- [X] Added feature flag 'your_service'
- [X] Updated error.rs reqwest cfg gate
- [X] HTTPS enforced, HTTP timeouts configured
- [X] Added integration tests (sign_message, sign_transaction, is_available)
- [X] Updated .env.example
- [X] Added to README.md supported backends table
- [X] CI Phase 2 changes included
- [X] TypeScript package with unit + integration tests
- [X] Umbrella package updated (types, create-signer, resolve-address, index, package.json, tsconfig)
- [X] Coordinated with maintainers on Phase 1 CI

Closes #1337
```

## Getting Help

- Review existing signer implementations for patterns:
  - [src/memory/mod.rs](../rust/src/memory/mod.rs) - Simple, synchronous
  - [src/privy/mod.rs](../rust/src/privy/mod.rs) - Requires initialization
  - [src/turnkey/mod.rs](../rust/src/turnkey/mod.rs) - Complex signature handling
  - [src/vault/mod.rs](../rust/src/vault/mod.rs) - External client library
  - [typescript/packages/para/](../typescript/packages/para/) - Complete TypeScript reference
- Open an issue for design discussions before starting work
- Check the trait definition in [src/traits.rs](../rust/src/traits.rs)

Welcome to the solana-keychain ecosystem! We're excited to have your key management solution as part of the library.
