//! Core trait definitions for Solana signers

use async_trait::async_trait;

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};

pub type SignedTransaction = (String, Signature);
#[derive(Debug)]
pub enum SignTransactionResult {
    Complete(SignedTransaction),
    Partial(SignedTransaction),
}

impl SignTransactionResult {
    pub fn into_signed_transaction(self) -> SignedTransaction {
        match self {
            Self::Complete(tx) | Self::Partial(tx) => tx,
        }
    }
}

/// Trait for signing Solana transactions
///
/// All signer implementations must implement this trait to provide
/// a unified interface for transaction signing.
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    /// Get the public key of this signer
    fn pubkey(&self) -> Pubkey;

    /// Sign a Solana transaction
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign (will be modified in place)
    ///
    /// # Returns
    ///
    /// The encoded transaction/signature tuple, explicitly marked as complete or partial.
    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignTransactionResult, SignerError>;

    /// Sign an arbitrary message
    ///
    /// # Arguments
    ///
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// The signature produced by signing the message
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;

    /// Check if the signer is available and healthy
    ///
    /// # Returns
    ///
    /// `true` if the signer can be used, `false` otherwise
    async fn is_available(&self) -> bool;
}
