//! Core trait definitions for Solana signers

use async_trait::async_trait;

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};

pub type SignedTransaction = (String, Signature);

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
    /// The base64 encoded transaction and signature
    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError>;

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

    /// Partially sign a transaction and return it as a base64-encoded string
    ///
    /// This method signs the transaction and serializes it with `requireAllSignatures: false`,
    /// making it suitable for multi-signature workflows where additional signatures will be
    /// added later.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign (will be modified in place)
    ///
    /// # Returns
    ///
    /// Base64-encoded partially-signed transaction
    async fn sign_partial_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError>;

    /// Check if the signer is available and healthy
    ///
    /// # Returns
    ///
    /// `true` if the signer can be used, `false` otherwise
    async fn is_available(&self) -> bool;
}
