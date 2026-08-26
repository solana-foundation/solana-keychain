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

/// Base trait every signer backend implements: identity, message signing and
/// health.
///
/// Transaction handling lives in the capability traits, and a backend
/// implements exactly the one matching its provider's shape:
///
/// - [`TransactionSigner`]: signs the caller's transaction as given and leaves
///   broadcasting to the caller.
/// - [`ModifyingSigner`]: rewrites the transaction before signing it; the
///   caller must continue from the returned transaction.
/// - [`SendingSigner`]: the provider signs and broadcasts server-side; the
///   caller's transaction is never mutated.
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    /// Get the public key of this signer
    fn pubkey(&self) -> Pubkey;

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

/// A signer that signs the caller's transaction exactly as given.
///
/// The transaction's message bytes are what the signature covers; the caller
/// broadcasts the result.
#[async_trait]
pub trait TransactionSigner: SolanaSigner {
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
}

/// A signer whose provider rewrites the transaction before signing it.
///
/// The returned signature covers the rewritten message, not the bytes the
/// caller supplied, so any signatures collected beforehand are invalidated.
/// Run a modifying signer first and continue from the transaction it returns.
#[async_trait]
pub trait ModifyingSigner: SolanaSigner {
    /// Let the provider rewrite `tx`, sign the rewritten transaction and
    /// replace `tx` with it.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to rewrite and sign. On success it holds the
    ///   provider's rewritten transaction; continue from it, never from the
    ///   bytes submitted.
    ///
    /// # Returns
    ///
    /// The encoded rewritten transaction/signature tuple, explicitly marked as
    /// complete or partial.
    async fn modify_and_sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError>;
}

/// A signer whose provider signs and broadcasts the transaction server-side.
///
/// The provider may rewrite the transaction before broadcasting; the caller's
/// transaction is never mutated, and the returned signature identifies the
/// transaction that actually landed. A failed call does not mean nothing
/// landed: [`SignerError::BroadcastUnconfirmed`] carries the provider
/// transaction id when the create was accepted.
#[async_trait]
pub trait SendingSigner: SolanaSigner {
    /// Sign a Solana transaction and broadcast it through the provider
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign and broadcast, left untouched.
    ///
    /// # Returns
    ///
    /// The signature identifying the broadcast transaction.
    async fn sign_and_send_transaction(
        &self,
        tx: &VersionedTransaction,
    ) -> Result<Signature, SignerError>;
}
