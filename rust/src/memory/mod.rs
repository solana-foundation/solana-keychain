//! Memory-based local keypair signer

mod keypair_util;

use crate::{
    error::SignerError,
    sdk_adapter::keypair_from_bytes,
    traits::{SignTransactionResult, SolanaSigner, TransactionSigner},
    transaction_util::TransactionUtil,
};

use crate::sdk_adapter::{
    keypair_pubkey, keypair_sign_message, Keypair, Pubkey, Signature, VersionedTransaction,
};
use keypair_util::KeypairUtil;

/// A Solana-based signer that uses an in-memory keypair
pub struct MemorySigner {
    keypair: Keypair,
}

/// Configuration for creating a MemorySigner.
pub struct MemorySignerConfig {
    pub keypair: Keypair,
}

impl std::fmt::Debug for MemorySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySigner")
            .field("pubkey", &keypair_pubkey(&self.keypair))
            .finish_non_exhaustive()
    }
}

impl MemorySigner {
    /// Creates a new signer from a Solana keypair
    pub fn new(keypair: Keypair) -> Self {
        Self::from_config(MemorySignerConfig { keypair })
    }

    /// Creates a new signer from a configuration object.
    pub fn from_config(config: MemorySignerConfig) -> Self {
        Self {
            keypair: config.keypair,
        }
    }

    /// Creates a new signer from a private key byte array
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        let keypair = keypair_from_bytes(private_key).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to build keypair from private key bytes: {_e}");
            SignerError::InvalidPrivateKey("Invalid private key bytes".to_string())
        })?;
        Ok(Self { keypair })
    }

    /// Creates a new signer from a private key string that can be in multiple formats:
    /// - Base58 encoded string
    /// - U8Array format: "[0, 1, 2, ...]"
    pub fn from_private_key_string(private_key: &str) -> Result<Self, SignerError> {
        let keypair = KeypairUtil::from_private_key_string(private_key)?;
        Ok(Self::new(keypair))
    }

    /// Creates a new signer from a JSON keypair file path.
    pub fn from_private_key_file(path: &str) -> Result<Self, SignerError> {
        let keypair = KeypairUtil::from_private_key_file(path)?;
        Ok(Self::new(keypair))
    }

    fn sign_bytes(&self, serialized: &[u8]) -> Signature {
        keypair_sign_message(&self.keypair, serialized)
    }
}

#[async_trait::async_trait]
impl SolanaSigner for MemorySigner {
    fn pubkey(&self) -> Pubkey {
        keypair_pubkey(&self.keypair)
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.sign_bytes(message))
    }

    async fn is_available(&self) -> bool {
        // Memory signer is always available
        true
    }
}

#[async_trait::async_trait]
impl TransactionSigner for MemorySigner {
    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signature = self.sign_bytes(&tx.message.serialize());
        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey(), signature)?;

        let signed_transaction = (TransactionUtil::serialize_transaction(tx)?, signature);
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }
}

#[cfg(test)]
mod tests;
