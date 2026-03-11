# Adding New Signers to solana-keychain

## Overview

This guide is for wallet service providers and developers who want to integrate new key management solutions into the `solana-keychain` library. By adding your signer implementation, you'll enable developers to use your service for secure Solana transaction signing through a unified interface.

We strongly prefer PRs that include both [Rust](#rust) and [TypeScript](#typescript) implementations — every signer contributed so far has shipped both. If you can only contribute one, that's fine, but expect the other to be required before the signer ships in a release.

> **Using Claude Code?** This repo includes an `add-signer` skill (`.claude/skills/add-signer/`) that orchestrates the full workflow below — including gotchas and file ordering that this guide doesn't cover.

---

## Rust

### Architecture Overview

The library uses a trait-based architecture where all signers implement the `SolanaSigner` trait defined in [src/traits.rs](../rust/src/traits.rs). The library also provides a unified `Signer` enum that wraps all implementations, allowing runtime selection of signing backends while maintaining a consistent API.

### Quick Checklist

- [ ] Create your signer module with implementation
- [ ] Implement the `SolanaSigner` trait
- [ ] Add a feature flag in `Cargo.toml`
- [ ] Update the `Signer` enum in `src/lib.rs`
- [ ] Update `src/error.rs` reqwest `From` impl cfg gate (if your signer uses reqwest)
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

use crate::{error::SignerError, traits::SolanaSigner};
use solana_sdk::{pubkey::Pubkey, signature::Signature, transaction::Transaction};
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

```rust
impl YourServiceSigner {
    /// Create a new YourServiceSigner
    ///
    /// # Arguments
    ///
    /// * `api_key` - YourService API key
    /// * `api_secret` - YourService API secret
    /// * `wallet_id` - YourService wallet ID
    /// * `public_key` - Base58-encoded Solana public key
    pub fn new(
        api_key: String,
        api_secret: String,
        wallet_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            api_key,
            api_secret,
            wallet_id,
            api_base_url: "https://api.yourservice.com/v1".to_string(),
            client: reqwest::Client::new(),
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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(SignerError::RemoteApiError(format!(
                "API error {status}: {error_text}"
            )));
        }

        // 3. Parse the response and extract signature
        let response_data: SignResponse = response.json().await?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response_data.signature)
            .map_err(|e| SignerError::SerializationError(format!("Failed to decode signature: {e}")))?;

        // 4. Convert to Solana signature (must be exactly 64 bytes)
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SignerError::SigningFailed("Invalid signature length".to_string()))?;

        Ok(Signature::from(sig_array))
    }
}
```

### Step 4: Implement the SolanaSigner Trait

```rust
#[async_trait::async_trait]
impl SolanaSigner for YourServiceSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_transaction(&self, tx: &mut Transaction) -> Result<Signature, SignerError> {
        // Serialize the transaction
        let serialized = bincode::serialize(tx).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;

        // Sign using your service
        self.sign(&serialized).await
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

Add your signer to `src/lib.rs`:

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
        )?))
    }
}

// Update trait implementation
#[async_trait::async_trait]
impl SolanaSigner for Signer {
    fn pubkey(&self) -> solana_sdk::pubkey::Pubkey {
        match self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService(s) => s.pubkey(),
        }
    }

    async fn sign_transaction(
        &self,
        tx: &mut solana_sdk::transaction::Transaction,
    ) -> Result<solana_sdk::signature::Signature, SignerError> {
        match self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService(s) => s.sign_transaction(tx).await,
        }
    }

    async fn sign_message(
        &self,
        message: &[u8],
    ) -> Result<solana_sdk::signature::Signature, SignerError> {
        match self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService(s) => s.sign_message(message).await,
        }
    }

    async fn is_available(&self) -> bool {
        match self {
            // ... existing variants
            #[cfg(feature = "your_service")]
            Signer::YourService(s) => s.is_available().await,
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
    feature = "para",
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
- [ ] Implement `SolanaSigner` interface from `@solana/keychain-core`
- [ ] Export `createXSigner()` factory function returning `SolanaSigner<TAddress>`
- [ ] Export `static create()` on the class
- [ ] Export config interface (`XSignerConfig`)
- [ ] Unit tests with vitest + mocks
- [ ] Integration tests using `runSignerIntegrationTest` + `setup.ts`
- [ ] Update umbrella package `typescript/packages/keychain/` (namespace export, class re-export, dependency)
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

Every signer must implement `SolanaSigner<TAddress>` from `@solana/keychain-core`. The interface requires:

- `readonly address: Address<TAddress>`
- `signMessages(messages): Promise<readonly SignatureDictionary[]>`
- `signTransactions(transactions): Promise<readonly SignatureDictionary[]>`
- `isAvailable(): Promise<boolean>` — health check for the signing backend

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

The factory function is the primary public API. It returns `SolanaSigner<TAddress>` (the interface), not the concrete class. Place it above the class definition, after imports.

**Async signer** (fetches public key during init — most common):

```typescript
import { SolanaSigner, SignerErrorCode, throwSignerError } from '@solana/keychain-core';

export async function createYourSigner<TAddress extends string = string>(
    config: YourSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await YourSigner.create(config);
}

export class YourSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
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
): SolanaSigner<TAddress> {
    return YourSigner.create(config);
}

export class YourSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;

    static create<TAddress extends string = string>(config: YourSignerConfig): YourSigner<TAddress> {
        return new YourSigner<TAddress>(config);
    }

    constructor(config: YourSignerConfig) {
        // validate config, set this.address from config.publicKey
    }

    // ... implement signMessages, signTransactions, isAvailable
}
```

**Key rules:**

- Wrap all `fetch()` calls in try/catch — use `throwSignerError(SignerErrorCode.HTTP_ERROR, { cause: error, ... })` from `@solana/keychain-core`
- Add `cause` to catch blocks to preserve stack traces
- Use `requestDelayMs` pattern if your API has rate limits (see any existing signer for the `delay()` + `validateRequestDelayMs()` pattern)

#### Index Exports

```typescript
// index.ts
export { YourSigner, createYourSigner } from './your-signer.js';
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

Update `typescript/packages/keychain/` to include your signer:

**`keychain/src/index.ts`** — add two lines:

```typescript
export * as yourSigner from '@solana/keychain-your-signer';

export { YourSigner } from '@solana/keychain-your-signer';
```

**`keychain/package.json`** — add to `dependencies`:

```json
"@solana/keychain-your-signer": "workspace:*"
```

**`keychain/tsconfig.json`** — add to `references`:

```json
{ "path": "../your-signer" }
```

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
    "version": "0.4.0",
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

---

## Submission Checklist

Before submitting your PR:

- [ ] Code compiles without warnings (`just build`)
- [ ] All tests pass (`just test`)
- [ ] Code is formatted/linting passes (`just fmt`)
- [ ] No hardcoded values or secrets in code
- [ ] Error messages are helpful and descriptive
- [ ] Follows naming conventions (snake_case for Rust, camelCase for TypeScript)
- [ ] `error.rs` reqwest cfg gate updated (if using reqwest)
- [ ] Integration test file added with standard test scenarios
- [ ] `.env.example` updated (root + TS package)
- [ ] Added to README.md supported backends table
- [ ] CI changes included
- [ ] TypeScript package with unit + integration tests
- [ ] Umbrella package updated (`keychain/src/index.ts`, `keychain/package.json`)
- [ ] Coordinated with maintainers on Phase 1 CI preparation

## Implementation Tips

### Error Handling

Always use the existing error types. If you need a new error type, propose it in your PR:

```rust
// Good - uses existing error types
return Err(SignerError::RemoteApiError(format!("API error: {}", status)));

// Good - converts from standard errors
let bytes = base64::decode(data)
    .map_err(|e| SignerError::SerializationError(format!("Failed to decode: {e}")))?;
```

### Security Best Practices

- Never log sensitive data (private keys, API secrets)
- Use `Debug` impl that hides sensitive fields
- Validate all inputs (public keys, signatures)
- Use HTTPS for API calls
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
- [X] Added integration tests (sign_message, sign_transaction, is_available)
- [X] Updated .env.example
- [X] Added to README.md supported backends table
- [X] CI Phase 2 changes included
- [X] TypeScript package with unit + integration tests
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
