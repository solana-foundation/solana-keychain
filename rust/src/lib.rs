//! Framework-agnostic Solana signing abstractions
//!
//! This crate provides a unified interface for signing Solana transactions
//! with multiple backend implementations (memory, Vault, Privy, Turnkey).
//!
//! # Features
//!
//! ## Signer Backends
//! - `memory` (default): Local keypair signing
//! - `vault`: HashiCorp Vault integration
//! - `privy`: Privy API integration
//! - `turnkey`: Turnkey API integration
//! - `all`: Enable all signer backends
//!
//! ## SDK Version Selection
//! - `sdk-v2` (default): Use Solana SDK v2.3.x
//! - `sdk-v3`: Use Solana SDK v3.x
//!
//! **Note**: Only one SDK version can be enabled at a time.

pub mod error;
mod sdk_adapter;
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

// Re-export core types
pub use error::SignerError;
pub use traits::SolanaSigner;

// Re-export signer types
#[cfg(feature = "memory")]
pub use memory::MemorySigner;

#[cfg(feature = "vault")]
pub use vault::VaultSigner;

#[cfg(feature = "privy")]
pub use privy::PrivySigner;

#[cfg(feature = "turnkey")]
pub use turnkey::TurnkeySigner;

use crate::traits::SignedTransaction;

// Ensure at least one signer backend is enabled
#[cfg(not(any(
    feature = "memory",
    feature = "vault",
    feature = "privy",
    feature = "turnkey"
)))]
compile_error!(
    "At least one signer backend feature must be enabled: memory, vault, privy, or turnkey"
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
}

impl Signer {
    /// Create a memory signer from a private key string
    #[cfg(feature = "memory")]
    pub fn from_memory(private_key: &str) -> Result<Self, SignerError> {
        Ok(Self::Memory(MemorySigner::from_private_key_string(
            private_key,
        )?))
    }

    /// Create a Vault signer
    #[cfg(feature = "vault")]
    pub fn from_vault(
        vault_addr: String,
        vault_token: String,
        key_name: String,
        pubkey: String,
    ) -> Result<Self, SignerError> {
        Ok(Self::Vault(VaultSigner::new(
            vault_addr,
            vault_token,
            key_name,
            pubkey,
        )?))
    }

    /// Create a Privy signer (requires initialization)
    #[cfg(feature = "privy")]
    pub async fn from_privy(
        app_id: String,
        app_secret: String,
        wallet_id: String,
    ) -> Result<Self, SignerError> {
        let mut signer = PrivySigner::new(app_id, app_secret, wallet_id);
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
        Ok(Self::Turnkey(TurnkeySigner::new(
            api_public_key,
            api_private_key,
            organization_id,
            private_key_id,
            public_key,
        )?))
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
        }
    }

    async fn sign_transaction(
        &self,
        tx: &mut sdk_adapter::Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.sign_transaction(tx).await,

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.sign_transaction(tx).await,
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
        }
    }

    async fn sign_partial_transaction(
        &self,
        tx: &mut sdk_adapter::Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        match self {
            #[cfg(feature = "memory")]
            Signer::Memory(s) => s.sign_partial_transaction(tx).await,

            #[cfg(feature = "vault")]
            Signer::Vault(s) => s.sign_partial_transaction(tx).await,

            #[cfg(feature = "privy")]
            Signer::Privy(s) => s.sign_partial_transaction(tx).await,

            #[cfg(feature = "turnkey")]
            Signer::Turnkey(s) => s.sign_partial_transaction(tx).await,
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
        }
    }
}
