# Adding New Signers to solana-keychain

## Overview

This guide is for wallet service providers and developers who want to integrate new key management solutions into the `solana-keychain` library. By adding your signer implementation, you'll enable Rust developers to use your service for secure Solana transaction signing through a unified interface.

## Architecture Overview

The library uses a trait-based architecture where all signers implement the `SolanaSigner` trait defined in [src/traits.rs](../src/traits.rs). The library also provides a unified `Signer` enum that wraps all implementations, allowing runtime selection of signing backends while maintaining a consistent API.

## Step-by-Step Integration Guide

### Quick Integration Checklist

- [ ] Create your signer module with implementation
- [ ] Implement the `SolanaSigner` trait
- [ ] Add a feature flag in `Cargo.toml`
- [ ] Update the `Signer` enum in `src/lib.rs`
- [ ] Add comprehensive tests
- [ ] Update documentation
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

### Step 9: Update Documentation

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

## Testing Your Integration

### Unit Tests

Run tests for your feature:

```bash
# Test only your signer
cargo test --features your_service

# Test with all features
cargo test --all-features
```

## Submission Checklist

Before submitting your PR:

- [ ] Code compiles without warnings (`just build`)
- [ ] All tests pass (`just test`)
- [ ] Code is formatted/linting passes (`just fmt`)
- [ ] No hardcoded values or secrets in code
- [ ] Error messages are helpful and descriptive
- [ ] Follows Rust naming conventions (snake_case)
- [ ] Added to README.md supported backends table

## Implementation Tips

### Error Handling

Always use the existing `SignerError` variants. If you need a new error type, propose it in your PR:

```rust
// Good - uses existing error types
return Err(SignerError::RemoteApiError(format!("API error: {}", status)));

// Good - converts from standard errors
let bytes = base64::decode(data)
    .map_err(|e| SignerError::SerializationError(format!("Failed to decode: {e}")))?;
```

### Async/Await

All signing operations must be async:

```rust
async fn sign(&self, message: &[u8]) -> Result<Signature, SignerError> {
    // Use .await for async operations
    let response = self.client.post(&url).send().await?;
    // ...
}
```

### Security Best Practices

- Never log sensitive data (private keys, API secrets)
- Use `Debug` impl that hides sensitive fields
- Validate all inputs (public keys, signatures)
- Use HTTPS for API calls
- Consider rate limiting and retry logic

### Testing with Mocks

Use `wiremock` for mocking HTTP APIs:

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

## Getting Help

- Review existing signer implementations for patterns:
  - [src/memory/mod.rs](../src/memory/mod.rs) - Simple, synchronous
  - [src/privy/mod.rs](../src/privy/mod.rs) - Requires initialization
  - [src/turnkey/mod.rs](../src/turnkey/mod.rs) - Complex signature handling
  - [src/vault/mod.rs](../src/vault/mod.rs) - External client library
- Open an issue for design discussions before starting work
- Check the trait definition in [src/traits.rs](../src/traits.rs)

## Example PR Structure

```
feat(signer): add YourService signer integration

Adds support for YourService as a signing backend. [Link to YourService Documentation](https://yourservice.com/docs)


- [X] Code compiles without warnings (`just build`)
- [X] Code is formatted/linting passes (`just fmt`)
- [X] Add comprehensive tests with wiremock - All tests pass (`just test`)
- [X] Implemented SolanaSigner trait for YourServiceSigner
- [X] Added feature flag 'your_service'
- [X] Added to README.md supported backends table

Closes #1337
```

Welcome to the solana-keychain ecosystem! We're excited to have your key management solution as part of the library.
