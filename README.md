# solana-keychain

**Flexible, framework-agnostic Solana transaction signing for Rust applications**

> ⚠️ **SECURITY NOTICE**: This library has not been audited. Use at your own risk. Not recommended for production use with real funds without a thorough security review. The authors and contributors are not responsible for any loss of funds or damages resulting from the use of this library.

`solana-keychain` provides a unified interface for signing Solana transactions with multiple backend implementations. Whether you need local keypairs for development, enterprise vault integration, or managed wallet services, this library offers a consistent API across all signing methods.

## Features

- **Unified Interface**: Single `SolanaSigner` trait for all backends
- **Async-First**: Built with `async/await` for modern Rust applications
- **Modular**: Feature flags for zero-cost backend selection
- **Type-Safe**: Compile-time guarantees and error handling
- **Minimal Dependencies**: Only include what you use

## Supported Backends

| Backend | Use Case | Feature Flag |
|---------|----------|--------------|
| **Memory** | Local keypairs, development, testing | `memory` (default) |
| **Vault** | Enterprise key management with HashiCorp Vault | `vault` |
| **Privy** | Embedded wallets with Privy infrastructure | `privy` |
| **Turnkey** | Non-custodial key management via Turnkey | `turnkey` |

## Installation

```toml
[dependencies]
# Basic usage (memory signer only)
solana-keychain = "0.1"

# With Vault support
solana-keychain = { version = "0.1", features = ["vault"] }

# All backends
solana-keychain = { version = "0.1", features = ["all"] }
```

## Quick Start

### Memory Signer (Local Development)

```rust
use solana_keychain::{MemorySigner, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer from private key
    let signer = MemorySigner::from_private_key_string(
        "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254...]"
    )?;

    // Get public key
    let pubkey = signer.pubkey();
    println!("Public key: {}", pubkey);

    // Sign a message
    let message = b"Hello Solana!";
    let signature = signer.sign_message(message).await?;
    println!("Signature: {}", signature);

    Ok(())
}
```

## Core API

All signers implement the `SolanaSigner` trait:

```rust
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    /// Get the public key of this signer
    fn pubkey(&self) -> Pubkey;

    /// Sign a Solana transaction (modifies transaction in place)
    async fn sign_transaction(&self, tx: &mut Transaction) -> Result<Signature, SignerError>;

    /// Sign arbitrary message bytes
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;

    /// Check if the signer is available and healthy
    async fn is_available(&self) -> bool;
}
```

## Contributing

### Local Development

```bash
make build
make test
make fmt
```

### Adding a New Signer Backend

Interested in adding a new signer backend? Check out our [guide for adding new signers](docs/ADDING_SIGNERS.md).