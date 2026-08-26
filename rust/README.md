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
| **Utila** | Utila MPC wallets and automated co-signer flow | `utila` |
| **Fordefi** | Fordefi institutional MPC custody with black-box and native Solana signing | `fordefi` |

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

# With Utila support
solana-keychain = { version = "0.5", features = ["utila"] }

# All backends
solana-keychain = { version = "0.5", features = ["all"] }
```

### Solana SDK version

The Solana SDK line is selected by a mutually-exclusive feature (exactly one is required):

| Feature | Solana SDK | Notes |
| --- | --- | --- |
| `sdk-v2` | `solana-sdk` 2.x | Default |
| `sdk-v3` | `solana-sdk` 3.x | |
| `sdk-v4` | `solana-sdk` 4.x | |

```toml
# Use the Solana 4.x SDK line with all backends
solana-keychain = { version = "0.5", default-features = false, features = ["all", "sdk-v4"] }
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

### Utila Signer

[Utila](https://www.utila.io/) signer for existing Solana wallets.

```rust
use solana_keychain::{Signer, SolanaSigner, UtilaSignerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Signer::from_utila(UtilaSignerConfig {
        service_account_email: std::env::var("UTILA_SERVICE_ACCOUNT_EMAIL")?,
        service_account_private_key_pem: std::env::var("UTILA_SERVICE_ACCOUNT_PRIVATE_KEY")?,
        vault_id: std::env::var("UTILA_VAULT_ID")?,
        wallet_id: std::env::var("UTILA_WALLET_ID")?,
        network: std::env::var("UTILA_NETWORK")?,
        api_base_url: std::env::var("UTILA_API_BASE_URL").ok(),
        poll_interval_ms: None,
        max_poll_attempts: None,
        designated_signers: None,
        http_client_config: None,
    }).await?;

    println!("Public key: {}", signer.pubkey());
    Ok(())
}
```

**Note:** Utila `sign_message` is intentionally unsupported in this signer and returns `SigningFailed`. Transaction signing requests are created with `publish=false`; callers remain responsible for broadcasting.

### Openfort Signer

[Openfort backend wallet](https://www.openfort.io/docs/products/server) signer for Solana transactions.

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

Every backend implements the `SolanaSigner` base trait, plus exactly the
capability trait matching its provider's shape:

```rust
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    /// Get the public key of this signer
    fn pubkey(&self) -> Pubkey;

    /// Sign arbitrary message bytes
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;

    /// Check if the signer is available and healthy
    async fn is_available(&self) -> bool;
}

/// Signs the caller's transaction as given; the caller broadcasts the result.
/// Accepts legacy, v0 and v1; v1 requires the `sdk-v4` feature.
#[async_trait]
pub trait TransactionSigner: SolanaSigner {
    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError>;
}

/// The provider rewrites the transaction before signing it; continue from the
/// returned transaction, never from the bytes submitted. No backend currently
/// implements this trait.
#[async_trait]
pub trait ModifyingSigner: SolanaSigner {
    async fn modify_and_sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError>;
}

/// The provider signs and broadcasts server-side; the caller's transaction is
/// never mutated, and the returned signature identifies what landed.
#[async_trait]
pub trait SendingSigner: SolanaSigner {
    async fn sign_and_send_transaction(
        &self,
        tx: &VersionedTransaction,
    ) -> Result<Signature, SignerError>;
}
```

### Signer capabilities

The capability trait a backend implements says whether the provider broadcasts;
whether it can sign arbitrary bytes is fixed per backend:

| Backend | Capability trait | `sign_message` |
|---------|------------------|----------------|
| memory, vault, privy, turnkey, aws-kms, fireblocks, gcp-kms, dfns, para, openfort | `TransactionSigner` | yes |
| cdp | `TransactionSigner` | UTF-8 payloads only, otherwise `SerializationError` |
| utila | `TransactionSigner` | `SigningFailed` |
| crossmint | `SendingSigner` | `SigningFailed` |
| fordefi black box (`FordefiBlackBoxSigner`) | `TransactionSigner` | yes |
| fordefi native (`FordefiNativeAutoSigner`) | `SendingSigner` | yes |

Crossmint executes every approved transaction server-side and exposes no
sign-only API, so it is a `SendingSigner` only. It may rewrite the
transaction to sponsor gas, in which case the returned signature identifies the
transaction it landed rather than covering the caller's bytes; the caller's
transaction is never modified.

The unified `Signer` enum wraps all backends in one type, so it implements
every capability trait; calling an entry point the wrapped backend lacks
returns `SigningFailed`. Direct use of the concrete signer types makes that
mismatch a compile error instead.

### Sign and Send

Getting a transaction on chain with one call depends on the signer's shape. A
`TransactionSigner` signs and a caller-supplied closure broadcasts the
base64-encoded result:

```rust
use solana_keychain::sign_and_send;

let signature = sign_and_send(&signer, &mut tx, |encoded| async move {
    rpc_send(encoded).await
})
.await?;
```

A `SendingSigner` broadcasts through its provider: call
`sign_and_send_transaction` directly. The unified `Signer` enum has its own
`sign_and_send` method covering both shapes; for a broadcasting backend the
closure is never called.

### Fordefi Signer

Fordefi comes as two signer types, which differ in whether Fordefi broadcasts the transaction and in which entry point exists. `config.chain` picks the type: `Signer::from_fordefi` builds a `FordefiBlackBoxSigner` when it is `None` and a `FordefiNativeAutoSigner` when it is set, and each type's `from_config` rejects a config meant for the other.

- **`FordefiBlackBoxSigner`** (`TransactionSigner`): Signs raw bytes via EdDSA; the wire transaction is assembled locally. Fordefi does **not** broadcast: `sign_transaction` returns the signed serialized transaction, and **you** submit it to an RPC. Use with a Fordefi black box vault.
- **`FordefiNativeAutoSigner`** (`SendingSigner`, recommended): Uses Solana-specific API types. Fordefi modifies the transaction (at minimum updating the blockhash, and optionally adding priority fees) and **auto-broadcasts** it on-chain (`push_mode: "auto"`). Call `sign_and_send_transaction`, which returns the signature, the on-chain identifier; do not re-send the transaction. The current auto-broadcast request supports only transactions whose sole required signer is the configured Fordefi vault; additional required signers are rejected before submission. Use with a regular Fordefi Solana vault.

The configured `public_key` is the source of truth for the vault's Solana
address: construction performs no network calls, and every signature Fordefi
returns is verified against this key before being accepted.

```rust
use solana_keychain::{FordefiBlackBoxSigner, FordefiSignerConfig, SolanaSigner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string("path/to/ecdsa-p256-key.pem")?;

    let signer = FordefiBlackBoxSigner::from_config(FordefiSignerConfig {
        access_token: std::env::var("FORDEFI_ACCESS_TOKEN")?,
        vault_id: std::env::var("FORDEFI_BB_VAULT_ID")?,
        private_key_pem: Some(pem.clone()),
        request_signer: None,
        public_key: std::env::var("FORDEFI_BB_PUBLIC_KEY")?,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        http_client_config: None,
        chain: None,
        fee: None,
    })
    .await?;

    println!("Public key: {}", signer.pubkey());
    Ok(())
}
```

For native Solana mode, set `chain` and optionally `fee`:

```rust
use solana_keychain::{
    FordefiNativeAutoSigner, FordefiSignerConfig, SolanaChainUniqueId,
    FordefiSolanaFee, FordefiPriorityLevel, SolanaSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string("path/to/ecdsa-p256-key.pem")?;

    let signer = FordefiNativeAutoSigner::from_config(FordefiSignerConfig {
        access_token: std::env::var("FORDEFI_ACCESS_TOKEN")?,
        vault_id: std::env::var("FORDEFI_VAULT_ID")?,
        private_key_pem: Some(pem),
        request_signer: None,
        public_key: std::env::var("FORDEFI_PUBLIC_KEY")?,
        api_base_url: None,
        poll_interval_ms: None,
        max_poll_attempts: None,
        http_client_config: None,
        chain: Some(SolanaChainUniqueId::SolanaMainnet),
        fee: Some(FordefiSolanaFee::Priority {
            priority_level: FordefiPriorityLevel::Medium,
        }),
    })
    .await?;

    let message = b"Hello from Fordefi!";
    let signature = signer.sign_message(message).await?;
    println!("Signature: {}", signature);

    Ok(())
}
```

#### Custom API-request signer (KMS/HSM)

Fordefi authenticates every POST with a request-level signature over
`{path}|{timestamp}|{body}` (ECDSA P-256, SHA-256, DER, base64). By default this is
computed locally from `private_key_pem`. To keep that key in a KMS/HSM instead,
implement [`FordefiRequestSigner`] and provide it as `request_signer` instead.
The implementation must return base64 of the DER-encoded ECDSA P-256 signature
over `SHA-256(payload)` (AWS KMS `Sign` with `ECDSA_SHA_256` already returns a
DER signature — just base64-encode it).

```rust
use std::sync::Arc;
use solana_keychain::{FordefiBlackBoxSigner, FordefiRequestSigner, FordefiSignerConfig, SignerError};

struct KmsRequestSigner { /* KMS client, key id, ... */ }

#[async_trait::async_trait]
impl FordefiRequestSigner for KmsRequestSigner {
    async fn sign_request(&self, payload: &[u8]) -> Result<String, SignerError> {
        // Call your KMS to sign SHA-256(payload) with ECDSA P-256, then base64-encode
        // the returned DER signature. `payload` is `{path}|{timestamp}|{body}`.
        todo!()
    }
}

let signer = FordefiBlackBoxSigner::from_config(FordefiSignerConfig {
    access_token: std::env::var("FORDEFI_ACCESS_TOKEN")?,
    vault_id: std::env::var("FORDEFI_VAULT_ID")?,
    private_key_pem: None,
    request_signer: Some(Arc::new(KmsRequestSigner { /* ... */ })),
    public_key: std::env::var("FORDEFI_PUBLIC_KEY")?,
    api_base_url: None,
    poll_interval_ms: None,
    max_poll_attempts: None,
    http_client_config: None,
    chain: None,
    fee: None,
})
.await?;
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

Interested in adding a new signer backend? Check out our [guide for adding new signers](../docs/ADDING_SIGNERS.md). If you use [Claude Code](https://claude.ai/code), the repo includes an `add-signer-ci` skill that wires up the CI workflows.
