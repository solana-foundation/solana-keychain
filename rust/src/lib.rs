//! Framework-agnostic Solana signing abstractions
//!
//! This crate provides a unified interface for signing Solana transactions
//! with multiple backend implementations (memory, Vault, Privy, Turnkey, AWS KMS, Para).
//!
//! # Features
//!
//! ## Signer Backends
//! - `memory` (default): Local keypair signing
//! - `vault`: HashiCorp Vault integration
//! - `privy`: Privy API integration
//! - `turnkey`: Turnkey API integration
//! - `aws_kms`: AWS KMS integration with EdDSA (Ed25519) signing
//! - `fireblocks`: Fireblocks API integration
//! - `gcp_kms`: GCP KMS integration with EdDSA (Ed25519) signing
//! - `cdp`: Coinbase Developer Platform integration
//! - `para`: Para MPC wallet integration
//! - `dfns`: Dfns Wallet API integration
//! - `all`: Enable all signer backends
//!
//! ## SDK Version Selection
//! - `sdk-v2` (default): Use Solana SDK v2.3.x
//! - `sdk-v3`: Use Solana SDK v3.x
//!
//! **Note**: Only one SDK version can be enabled at a time.

pub mod error;
pub mod http_client_config;
mod sdk_adapter;
pub mod signature_util;
#[cfg(test)]
pub mod test_util;
#[cfg(feature = "integration-tests")]
pub mod tests;
pub mod traits;
pub mod transaction_util;

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "privy")]
pub mod privy;

#[cfg(feature = "turnkey")]
pub mod turnkey;

#[cfg(feature = "aws_kms")]
pub mod aws_kms;

#[cfg(feature = "fireblocks")]
pub mod fireblocks;

#[cfg(feature = "gcp_kms")]
pub mod gcp_kms;

#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "dfns")]
pub mod dfns;
#[cfg(feature = "para")]
pub mod para;

// Re-export core types
pub use error::SignerError;
pub use http_client_config::HttpClientConfig;
pub use traits::{SignTransactionResult, SolanaSigner};

// Re-export signer types
#[cfg(feature = "memory")]
pub use memory::MemorySigner;

#[cfg(feature = "vault")]
pub use vault::VaultSigner;

#[cfg(feature = "privy")]
pub use privy::PrivySigner;

#[cfg(feature = "turnkey")]
pub use turnkey::TurnkeySigner;

#[cfg(feature = "aws_kms")]
pub use aws_kms::AwsKmsSigner;

#[cfg(feature = "fireblocks")]
pub use fireblocks::{FireblocksSigner, FireblocksSignerConfig};

#[cfg(feature = "gcp_kms")]
pub use gcp_kms::GcpKmsSigner;

#[cfg(feature = "cdp")]
pub use cdp::CdpSigner;
#[cfg(feature = "dfns")]
pub use dfns::{DfnsSigner, DfnsSignerConfig};
#[cfg(feature = "para")]
pub use para::ParaSigner;

// Ensure at least one signer backend is enabled
#[cfg(not(any(
    feature = "memory",
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "aws_kms",
    feature = "fireblocks",
    feature = "gcp_kms",
    feature = "cdp",
    feature = "dfns",
    feature = "para"
)))]
compile_error!(
    "At least one signer backend feature must be enabled: memory, vault, privy, turnkey, aws_kms, fireblocks, gcp_kms, cdp, para, or dfns"
);

/// Unified signer enum supporting multiple backends
pub enum Signer {
    #[cfg(feature = "memory")]
    Memory(MemorySigner),

    #[cfg(feature = "vault")]
    Vault(VaultSigner),

    #[cfg(feature = "privy")]
    Privy(PrivySigner),

    #[cfg(feature = "turnkey")]
    Turnkey(TurnkeySigner),

    #[cfg(feature = "aws_kms")]
    AwsKms(AwsKmsSigner),

    #[cfg(feature = "fireblocks")]
    Fireblocks(FireblocksSigner),

    #[cfg(feature = "gcp_kms")]
    GcpKms(GcpKmsSigner),

    #[cfg(feature = "cdp")]
    Cdp(CdpSigner),
    #[cfg(feature = "dfns")]
    Dfns(DfnsSigner),
    #[cfg(feature = "para")]
    Para(ParaSigner),
}

impl Signer {
    /// Create a memory signer from a private key string
    #[cfg(feature = "memory")]
    pub fn from_memory(private_key: &str) -> Result<Self, SignerError> {
        Ok(Self::Memory(MemorySigner::from_private_key_string(
            private_key,
        )?))
    }

    /// Create a memory signer from a JSON keypair file path
    #[cfg(feature = "memory")]
    pub fn from_memory_file(path: &str) -> Result<Self, SignerError> {
        Ok(Self::Memory(MemorySigner::from_private_key_file(path)?))
    }

    /// Create a Vault signer
    #[cfg(feature = "vault")]
    pub fn from_vault(
        vault_addr: String,
        vault_token: String,
        key_name: String,
        pubkey: String,
    ) -> Result<Self, SignerError> {
        Self::from_vault_with_http_client_config(vault_addr, vault_token, key_name, pubkey, None)
    }

    /// Create a Vault signer with custom HTTP timeout settings.
    #[cfg(feature = "vault")]
    pub fn from_vault_with_http_client_config(
        vault_addr: String,
        vault_token: String,
        key_name: String,
        pubkey: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Vault(VaultSigner::new_with_http_client_config(
            vault_addr,
            vault_token,
            key_name,
            pubkey,
            http_client_config,
        )?))
    }

    /// Create a Privy signer (requires initialization)
    #[cfg(feature = "privy")]
    pub async fn from_privy(
        app_id: String,
        app_secret: String,
        wallet_id: String,
    ) -> Result<Self, SignerError> {
        Self::from_privy_with_http_client_config(app_id, app_secret, wallet_id, None).await
    }

    /// Create a Privy signer with custom HTTP timeout settings (requires initialization).
    #[cfg(feature = "privy")]
    pub async fn from_privy_with_http_client_config(
        app_id: String,
        app_secret: String,
        wallet_id: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let mut signer = PrivySigner::new_with_http_client_config(
            app_id,
            app_secret,
            wallet_id,
            http_client_config,
        );
        signer.init().await?;
        Ok(Self::Privy(signer))
    }

    /// Create a Turnkey signer
    #[cfg(feature = "turnkey")]
    pub fn from_turnkey(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        Self::from_turnkey_with_http_client_config(
            api_public_key,
            api_private_key,
            organization_id,
            private_key_id,
            public_key,
            None,
        )
    }

    /// Create a Turnkey signer with custom HTTP timeout settings.
    #[cfg(feature = "turnkey")]
    pub fn from_turnkey_with_http_client_config(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Turnkey(TurnkeySigner::new_with_http_client_config(
            api_public_key,
            api_private_key,
            organization_id,
            private_key_id,
            public_key,
            http_client_config,
        )?))
    }

    /// Create an AWS KMS signer (requires initialization)
    #[cfg(feature = "aws_kms")]
    pub async fn from_aws_kms(
        key_id: String,
        public_key: String,
        region: Option<String>,
    ) -> Result<Self, SignerError> {
        Ok(Self::AwsKms(
            AwsKmsSigner::new(key_id, public_key, region).await?,
        ))
    }

    /// Create a Fireblocks signer (requires initialization)
    #[cfg(feature = "fireblocks")]
    pub async fn from_fireblocks(config: FireblocksSignerConfig) -> Result<Self, SignerError> {
        let mut signer = FireblocksSigner::new(config);
        signer.init().await?;
        Ok(Self::Fireblocks(signer))
    }

    /// Create a GCP KMS signer (requires initialization)
    #[cfg(feature = "gcp_kms")]
    pub async fn from_gcp_kms(key_name: String, public_key: String) -> Result<Self, SignerError> {
        Ok(Self::GcpKms(GcpKmsSigner::new(key_name, public_key).await?))
    }

    /// Create a Para signer (requires initialization)
    #[cfg(feature = "para")]
    pub async fn from_para(
        api_key: String,
        wallet_id: String,
        api_base_url: Option<String>,
    ) -> Result<Self, SignerError> {
        let mut signer = ParaSigner::new(api_key, wallet_id, api_base_url)?;
        signer.init().await?;
        Ok(Self::Para(signer))
    }

    /// Create a CDP signer
    #[cfg(feature = "cdp")]
    pub fn from_cdp(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
    ) -> Result<Self, SignerError> {
        Self::from_cdp_with_http_client_config(
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            None,
        )
    }

    /// Create a CDP signer with custom HTTP timeout settings.
    #[cfg(feature = "cdp")]
    pub fn from_cdp_with_http_client_config(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Cdp(CdpSigner::new_with_http_client_config(
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            http_client_config,
        )?))
    }

    /// Create a Dfns signer (requires initialization)
    #[cfg(feature = "dfns")]
    pub async fn from_dfns(config: DfnsSignerConfig) -> Result<Self, SignerError> {
        let mut signer = DfnsSigner::new(config);
        signer.init().await?;
        Ok(Self::Dfns(signer))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for Signer {
    fn pubkey(&self) -> sdk_adapter::Pubkey {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.pubkey(),

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.pubkey(),

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.pubkey(),

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.pubkey(),

            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => s.pubkey(),

            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => s.pubkey(),

            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => s.pubkey(),

            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => s.pubkey(),
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => s.pubkey(),
            #[cfg(feature = "para")]
            Signer::Para(s) => s.pubkey(),
        }
    }

    async fn sign_transaction(
        &self,
        tx: &mut sdk_adapter::Transaction,
    ) -> Result<SignTransactionResult, SignerError> {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.sign_transaction(tx).await,
        }
    }

    async fn sign_message(&self, message: &[u8]) -> Result<sdk_adapter::Signature, SignerError> {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.sign_message(message).await,

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.sign_message(message).await,

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.sign_message(message).await,

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.sign_message(message).await,

            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => s.sign_message(message).await,

            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => s.sign_message(message).await,

            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => s.sign_message(message).await,

            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => s.sign_message(message).await,
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => s.sign_message(message).await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.sign_message(message).await,
        }
    }

    async fn is_available(&self) -> bool {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.is_available().await,

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.is_available().await,

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.is_available().await,

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.is_available().await,

            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => s.is_available().await,

            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => s.is_available().await,

            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => s.is_available().await,

            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => s.is_available().await,
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => s.is_available().await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.is_available().await,
        }
    }
}
