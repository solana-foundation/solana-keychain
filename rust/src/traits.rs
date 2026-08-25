//! Core trait definitions for Solana signers

use async_trait::async_trait;

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};

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

    /// Returns `true` when the provider may execute the transaction server-side, requiring reconciliation by provider transaction ID before retrying.
    fn broadcasts_transactions(&self) -> bool {
        false
    }

    /// Sign a Solana transaction
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign (will be modified in place). Legacy, v0
    ///   and v1 are accepted; convert a legacy `Transaction` with `.into()`.
    ///   v1 requires `sdk-v4`.
    ///
    /// # Returns
    ///
    /// The encoded transaction/signature tuple, explicitly marked as complete or partial.
    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError>;

    /// Sign a Solana transaction and broadcast it through the provider
    ///
    /// Implemented only by signers whose provider executes the transaction
    /// server-side; every other signer signs and leaves broadcasting to the
    /// caller. [`broadcasts_transactions`](Self::broadcasts_transactions) reports
    /// which shape a signer has in its current configuration.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign and broadcast. The provider may rewrite
    ///   it, in which case `tx` is left untouched and the returned signature
    ///   identifies the transaction that actually landed.
    ///
    /// # Returns
    ///
    /// The signature identifying the broadcast transaction.
    ///
    /// # Errors
    ///
    /// [`SignerError::SigningFailed`] when this signer cannot broadcast.
    async fn sign_and_send_transaction(
        &self,
        _tx: &mut VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        Err(SignerError::SigningFailed(
            "This signer cannot broadcast transactions; sign it and broadcast the result"
                .to_string(),
        ))
    }

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
