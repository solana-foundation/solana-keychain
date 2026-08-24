//! Framework-agnostic Solana signing abstractions
//!
//! This crate provides a unified interface for signing Solana transactions
//! with multiple backend implementations (memory, Vault, Privy, Turnkey, AWS KMS,
//! Fireblocks, GCP KMS, Dfns, Crossmint, CDP, Para, Openfort, Utila, Fordefi).
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
//! - `crossmint`: Crossmint wallet integration
//! - `openfort`: Openfort backend wallet integration
//! - `utila`: Utila MPC wallet integration
//! - `fordefi`: Fordefi MPC custody integration
//! - `all`: Enable all signer backends
//!
//! ## SDK Version Selection
//! - `sdk-v2` (default): Use Solana SDK v2.3.x
//! - `sdk-v3`: Use Solana SDK v3.x
//! - `sdk-v4`: Use Solana SDK v4.x
//!
//! **Note**: Only one SDK version can be enabled at a time.

pub mod error;
pub mod http_client_config;
#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
))]
mod remote_util;
mod sdk_adapter;
pub mod signature_util;
#[cfg(test)]
pub mod test_util;
#[cfg(feature = "integration-tests")]
pub mod tests;
pub mod traits;
pub mod transaction_util;
#[cfg(any(feature = "cdp", feature = "openfort"))]
mod wallet_jwt;

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
#[cfg(feature = "crossmint")]
pub mod crossmint;
#[cfg(feature = "dfns")]
pub mod dfns;
#[cfg(feature = "fordefi")]
pub mod fordefi;
#[cfg(feature = "openfort")]
pub mod openfort;
#[cfg(feature = "para")]
pub mod para;
#[cfg(feature = "utila")]
pub mod utila;

// Re-export core types
pub use error::SignerError;
pub use http_client_config::HttpClientConfig;
pub use traits::{SignTransactionResult, SolanaSigner};

// Re-export signer types
#[cfg(feature = "memory")]
pub use memory::{MemorySigner, MemorySignerConfig};

#[cfg(feature = "vault")]
pub use vault::{VaultSigner, VaultSignerConfig};

#[cfg(feature = "privy")]
pub use privy::{PrivyAuthorizationRequestExpiry, PrivySigner, PrivySignerConfig};

#[cfg(feature = "turnkey")]
pub use turnkey::{TurnkeySigner, TurnkeySignerConfig};

#[cfg(feature = "aws_kms")]
pub use aws_kms::{AwsKmsSigner, AwsKmsSignerConfig};

#[cfg(feature = "fireblocks")]
pub use fireblocks::{FireblocksSigner, FireblocksSignerConfig};

#[cfg(feature = "gcp_kms")]
pub use gcp_kms::{GcpKmsSigner, GcpKmsSignerConfig};

#[cfg(feature = "cdp")]
pub use cdp::{CdpSigner, CdpSignerConfig};
#[cfg(feature = "crossmint")]
pub use crossmint::{CrossmintSigner, CrossmintSignerConfig};
#[cfg(feature = "dfns")]
pub use dfns::{DfnsSigner, DfnsSignerConfig};
#[cfg(feature = "fordefi")]
pub use fordefi::{
    FordefiPriorityLevel, FordefiRequestSigner, FordefiSigner, FordefiSignerConfig,
    FordefiSolanaFee, PemRequestSigner, SolanaChainUniqueId,
};
#[cfg(feature = "openfort")]
pub use openfort::{OpenfortSigner, OpenfortSignerConfig};
#[cfg(feature = "para")]
pub use para::{ParaSigner, ParaSignerConfig};
#[cfg(feature = "utila")]
pub use utila::{UtilaSigner, UtilaSignerConfig};

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
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
)))]
compile_error!(
    "At least one signer backend feature must be enabled: memory, vault, privy, turnkey, aws_kms, fireblocks, gcp_kms, cdp, para, dfns, crossmint, openfort, utila, or fordefi"
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
    #[cfg(feature = "openfort")]
    Openfort(OpenfortSigner),
    #[cfg(feature = "para")]
    Para(ParaSigner),
    #[cfg(feature = "crossmint")]
    Crossmint(CrossmintSigner),
    #[cfg(feature = "utila")]
    Utila(UtilaSigner),
    #[cfg(feature = "fordefi")]
    Fordefi(FordefiSigner),
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

    /// Create a Vault signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "vault")]
    pub fn from_vault(
        vault_addr: String,
        vault_token: String,
        key_name: String,
        pubkey: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Vault(VaultSigner::from_config(VaultSignerConfig {
            api_base_url: vault_addr,
            token: vault_token,
            key_name,
            public_key: pubkey,
            http_client_config,
        })?))
    }

    /// Create a Privy signer (requires initialization).
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "privy")]
    pub async fn from_privy(
        app_id: String,
        app_secret: String,
        wallet_id: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let mut signer = PrivySigner::from_config(PrivySignerConfig {
            app_id,
            app_secret,
            wallet_id,
            api_base_url: None,
            http_client_config,
            authorization_context: None,
            authorization_request_expiry: PrivyAuthorizationRequestExpiry::Default,
        })?;
        signer.init().await?;
        Ok(Self::Privy(signer))
    }

    /// Create a Turnkey signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "turnkey")]
    pub fn from_turnkey(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Turnkey(TurnkeySigner::from_config(
            TurnkeySignerConfig {
                api_public_key,
                api_private_key,
                organization_id,
                private_key_id,
                public_key,
                api_base_url: None,
                http_client_config,
            },
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
            AwsKmsSigner::from_config(AwsKmsSignerConfig {
                key_id,
                public_key,
                region,
            })
            .await?,
        ))
    }

    /// Create a Fireblocks signer (requires initialization)
    #[cfg(feature = "fireblocks")]
    pub async fn from_fireblocks(config: FireblocksSignerConfig) -> Result<Self, SignerError> {
        let mut signer = FireblocksSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Fireblocks(signer))
    }

    /// Create a GCP KMS signer (requires initialization)
    #[cfg(feature = "gcp_kms")]
    pub async fn from_gcp_kms(key_name: String, public_key: String) -> Result<Self, SignerError> {
        Ok(Self::GcpKms(
            GcpKmsSigner::from_config(GcpKmsSignerConfig {
                key_name,
                public_key,
            })
            .await?,
        ))
    }

    /// Create a Para signer (requires initialization)
    #[cfg(feature = "para")]
    pub async fn from_para(
        api_key: String,
        wallet_id: String,
        api_base_url: Option<String>,
    ) -> Result<Self, SignerError> {
        let mut signer = ParaSigner::from_config(ParaSignerConfig {
            api_key,
            wallet_id,
            api_base_url,
        })?;
        signer.init().await?;
        Ok(Self::Para(signer))
    }

    /// Create a CDP signer.
    ///
    /// Pass `None` for `http_client_config` to use default timeout settings.
    #[cfg(feature = "cdp")]
    pub fn from_cdp(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        Ok(Self::Cdp(CdpSigner::from_config(CdpSignerConfig {
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            api_base_url: None,
            http_client_config,
        })?))
    }

    /// Create a Dfns signer (requires initialization)
    #[cfg(feature = "dfns")]
    pub async fn from_dfns(config: DfnsSignerConfig) -> Result<Self, SignerError> {
        let mut signer = DfnsSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Dfns(signer))
    }

    /// Create a Crossmint signer (requires initialization)
    #[cfg(feature = "crossmint")]
    pub async fn from_crossmint(config: CrossmintSignerConfig) -> Result<Self, SignerError> {
        let mut signer = CrossmintSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Crossmint(signer))
    }

    /// Create an Openfort backend wallet signer.
    ///
    /// Fetches the wallet's Solana address from `GET /v2/accounts/{account_id}`
    /// during initialization. Pass `None` for `http_client_config` to use
    /// default timeout settings.
    #[cfg(feature = "openfort")]
    pub async fn from_openfort(
        secret_key: String,
        account_id: String,
        wallet_secret: String,
        http_client_config: Option<HttpClientConfig>,
    ) -> Result<Self, SignerError> {
        let mut signer = OpenfortSigner::from_config(OpenfortSignerConfig {
            secret_key,
            account_id,
            wallet_secret,
            api_base_url: None,
            http_client_config,
        })?;
        signer.init().await?;
        Ok(Self::Openfort(signer))
    }

    /// Create a Utila signer from an existing Solana wallet.
    ///
    /// Fetches the wallet's Solana address from Utila during initialization.
    #[cfg(feature = "utila")]
    pub async fn from_utila(config: UtilaSignerConfig) -> Result<Self, SignerError> {
        let mut signer = UtilaSigner::new(config)?;
        signer.init().await?;
        Ok(Self::Utila(signer))
    }

    /// Create a Fordefi signer.
    ///
    /// Fetches the vault during initialization and verifies that its authoritative
    /// Solana address matches `config.public_key`. Set `config.chain` to use native
    /// Solana mode (Fordefi modifies and auto-broadcasts the transaction). Leave it
    /// `None` for black-box mode (raw EdDSA signing, transaction assembled locally).
    #[cfg(feature = "fordefi")]
    pub async fn from_fordefi(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        Ok(Self::Fordefi(FordefiSigner::from_config(config).await?))
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
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => s.pubkey(),
            #[cfg(feature = "para")]
            Signer::Para(s) => s.pubkey(),
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => s.pubkey(),
            #[cfg(feature = "utila")]
            Signer::Utila(s) => s.pubkey(),
            #[cfg(feature = "fordefi")]
            Signer::Fordefi(s) => s.pubkey(),
        }
    }

    fn broadcasts_transactions(&self) -> bool {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.broadcasts_transactions(),

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.broadcasts_transactions(),

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.broadcasts_transactions(),

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.broadcasts_transactions(),

            #[cfg(feature = "aws_kms")]
            Signer::AwsKms(s) => s.broadcasts_transactions(),

            #[cfg(feature = "fireblocks")]
            Signer::Fireblocks(s) => s.broadcasts_transactions(),

            #[cfg(feature = "gcp_kms")]
            Signer::GcpKms(s) => s.broadcasts_transactions(),

            #[cfg(feature = "cdp")]
            Signer::Cdp(s) => s.broadcasts_transactions(),
            #[cfg(feature = "dfns")]
            Signer::Dfns(s) => s.broadcasts_transactions(),
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => s.broadcasts_transactions(),
            #[cfg(feature = "para")]
            Signer::Para(s) => s.broadcasts_transactions(),
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => s.broadcasts_transactions(),
            #[cfg(feature = "utila")]
            Signer::Utila(s) => s.broadcasts_transactions(),
            #[cfg(feature = "fordefi")]
            Signer::Fordefi(s) => s.broadcasts_transactions(),
        }
    }

    async fn sign_transaction(
        &self,
        tx: &mut sdk_adapter::VersionedTransaction,
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
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "utila")]
            Signer::Utila(s) => s.sign_transaction(tx).await,
            #[cfg(feature = "fordefi")]
            Signer::Fordefi(s) => s.sign_transaction(tx).await,
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
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => s.sign_message(message).await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.sign_message(message).await,
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => s.sign_message(message).await,
            #[cfg(feature = "utila")]
            Signer::Utila(s) => s.sign_message(message).await,
            #[cfg(feature = "fordefi")]
            Signer::Fordefi(s) => s.sign_message(message).await,
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
            #[cfg(feature = "openfort")]
            Signer::Openfort(s) => s.is_available().await,
            #[cfg(feature = "para")]
            Signer::Para(s) => s.is_available().await,
            #[cfg(feature = "crossmint")]
            Signer::Crossmint(s) => s.is_available().await,
            #[cfg(feature = "utila")]
            Signer::Utila(s) => s.is_available().await,
            #[cfg(feature = "fordefi")]
            Signer::Fordefi(s) => s.is_available().await,
        }
    }
}

#[cfg(all(test, feature = "crossmint"))]
mod signer_tests {
    use super::*;

    #[test]
    fn unified_signer_surfaces_broadcast_capability() {
        let signer = Signer::Crossmint(
            CrossmintSigner::new(CrossmintSignerConfig {
                api_key: "test-api-key".to_string(),
                wallet_locator: "test-wallet".to_string(),
                signer_secret: None,
                signer: None,
                api_base_url: Some("https://example.com".to_string()),
                poll_interval_ms: None,
                max_poll_attempts: None,
            })
            .unwrap(),
        );

        assert!(signer.broadcasts_transactions());
    }
}
