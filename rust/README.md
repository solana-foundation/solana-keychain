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
| **AWS KMS** | AWS Key Management Service with EdDSA (Ed25519) signing | `aws_kms` |

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

### AWS KMS Signer

```rust
use solana_keychain::{KmsSigner, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer using AWS KMS
    // Credentials are loaded from the AWS default credential chain
    let signer = KmsSigner::new(
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string(),
        "YourSolanaPublicKeyBase58".to_string(),
        Some("us-east-1".to_string()), // Optional region
    ).await?;

    // Sign a message
    let message = b"Hello Solana!";
    let signature = signer.sign_message(message).await?;
    println!("Signature: {}", signature);

    Ok(())
}
```

#### AWS Credentials

The AWS KMS signer uses the **AWS default credential provider chain**. Credentials are automatically loaded from:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Shared credentials file**: `~/.aws/credentials`
3. **IAM role** (automatic on EC2, ECS, Lambda)
4. **Web identity token** (for EKS/Kubernetes with IRSA)

| Environment | Recommended Method |
|-------------|-------------------|
| **Production on AWS** | IAM role (no explicit credentials needed) |
| **Local development** | Environment variables or `~/.aws/credentials` |
| **CI/CD pipelines** | Environment variables or OIDC |

#### Creating an AWS KMS Key

```bash
aws kms create-key \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description "Solana signing key"
```

Required IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["kms:Sign", "kms:DescribeKey"],
        "Resource": "arn:aws:kms:*:*:key/*"
    }]
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

Local development and testing use [Just](https://github.com/casey/just) as a build and development tool--make sure to install it before running any commands.

```bash
just build
just test
just fmt
```

### Adding a New Signer Backend

Interested in adding a new signer backend? Check out our [guide for adding new signers](docs/ADDING_SIGNERS.md).