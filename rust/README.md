# solana-keychain

**Flexible, framework-agnostic Solana transaction signing for Rust applications**

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
| **Fireblocks** | Fireblocks institutional custody platform | `fireblocks` |
| **GCP KMS** | Google Cloud Key Management Service with Ed25519 signing | `gcp_kms` |
| **Dfns** | Dfns wallet infrastructure with Ed25519 signing | `dfns` |
| **Para** | MPC wallets with Para infrastructure | `para` |
| **CDP** | Coinbase Developer Platform managed wallet infrastructure | `cdp` |
| **Crossmint** | Crossmint managed wallets (`smart` and `mpc`) | `crossmint` |
| **Openfort** | Openfort backend wallets with TEE-stored keys | `openfort` |

## Installation

```toml
[dependencies]
# Basic usage (memory signer only)
solana-keychain = "0.5"

# With CDP support
solana-keychain = { version = "0.5", features = ["cdp"] }

# With Vault support
solana-keychain = { version = "0.5", features = ["vault"] }

# With Crossmint support
solana-keychain = { version = "0.5", features = ["crossmint"] }

# With Openfort support
solana-keychain = { version = "0.5", features = ["openfort"] }

# All backends
solana-keychain = { version = "0.5", features = ["all"] }
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

**Note:** CDP's `sign_message` API only accepts UTF-8 messages. Non-UTF-8 byte payloads will return an error.

### AWS KMS Signer

```rust
use solana_keychain::{AwsKmsSigner, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer using AWS KMS
    // Credentials are loaded from the AWS default credential chain
    let signer = AwsKmsSigner::new(
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

### CDP Signer (Coinbase Developer Platform)

```rust
use solana_keychain::{CdpSigner, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer using CDP managed wallet infrastructure
    // API keys are created at https://portal.cdp.coinbase.com
    let signer = CdpSigner::new(
        std::env::var("CDP_API_KEY_ID")?,   // CDP API key ID
        std::env::var("CDP_API_KEY_SECRET")?,    // Base64 Ed25519 key
        std::env::var("CDP_WALLET_SECRET")?,  // Base64-encoded wallet secret
        std::env::var("CDP_SOLANA_ADDRESS")?, // Solana account address
    ).await?;

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

**Note:** CDP's `sign_message` API only accepts UTF-8 messages. Non-UTF-8 byte payloads will return an error.

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

### Para Signer

```rust
use solana_keychain::{Signer, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer using Para's MPC wallet API
    // API key must start with "sk_", wallet ID must be a valid UUID
    let signer = Signer::from_para(
        "sk_your-api-key".to_string(),
        "your-wallet-uuid".to_string(),
        None, // defaults to https://api.getpara.com
    ).await?;

    // Sign a message
    let message = b"Hello Solana!";
    let signature = signer.sign_message(message).await?;
    println!("Signature: {}", signature);

    Ok(())
}
```

### Crossmint Signer

```rust
use solana_keychain::{CrossmintSigner, CrossmintSignerConfig, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut signer = CrossmintSigner::new(CrossmintSignerConfig {
        api_key: std::env::var("CROSSMINT_API_KEY")?,
        wallet_locator: std::env::var("CROSSMINT_WALLET_LOCATOR")?,
        signer: std::env::var("CROSSMINT_SIGNER").ok(), // optional
        api_base_url: std::env::var("CROSSMINT_API_BASE_URL").ok(), // optional
        poll_interval_ms: None,
        max_poll_attempts: None,
    })?;

    signer.init().await?;

    println!("Public key: {}", signer.pubkey());
    Ok(())
}
```

**Note:** Crossmint `sign_message` is intentionally unsupported in this signer and returns `SigningFailed`.

### Openfort Signer

```rust
use solana_keychain::{Signer, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signer using an Openfort backend wallet.
    // The wallet's Solana address is fetched automatically during init.
    let signer = Signer::from_openfort(
        std::env::var("OPENFORT_SECRET_KEY")?,    // sk_test_* / sk_live_*
        std::env::var("OPENFORT_ACCOUNT_ID")?,    // acc_<uuid>
        std::env::var("OPENFORT_WALLET_SECRET")?, // base64 PKCS#8 DER or PEM
        None, // defaults to https://api.openfort.io with default timeouts
    ).await?;

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

## Security Audit

`solana-keychain` has been audited by [Accretion](https://accretion.xyz). View the [audit report](../audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf).

Audit status, audited-through commit, and the current unaudited delta are tracked in [audits/AUDIT_STATUS.md](../audits/AUDIT_STATUS.md).

## Contributing

### Local Development

Local development and testing use [Just](https://github.com/casey/just) as a build and development tool--make sure to install it before running any commands.

```bash
just build
just test
just fmt
```

### Adding a New Signer Backend

Interested in adding a new signer backend? Check out our [guide for adding new signers](docs/ADDING_SIGNERS.md). If you use [Claude Code](https://claude.ai/code), the repo includes an `add-signer` skill that walks you through the full process.
