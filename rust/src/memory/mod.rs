//! Memory-based local keypair signer

mod keypair_util;

use crate::{
    error::SignerError,
    sdk_adapter::keypair_from_bytes,
    traits::{SignedTransaction, SolanaSigner},
    transaction_util::TransactionUtil,
};

use crate::sdk_adapter::{
    keypair_pubkey, keypair_sign_message, Keypair, Pubkey, Signature, Transaction,
};
use keypair_util::KeypairUtil;

/// A Solana-based signer that uses an in-memory keypair
pub struct MemorySigner {
    keypair: Keypair,
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
        Self { keypair }
    }

    /// Creates a new signer from a private key byte array
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        let keypair = keypair_from_bytes(private_key).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("Invalid private key bytes: {e}"))
        })?;
        Ok(Self { keypair })
    }

    /// Creates a new signer from a private key string that can be in multiple formats:
    /// - Base58 encoded string
    /// - U8Array format: "[0, 1, 2, ...]"
    /// - File path to a JSON keypair file
    pub fn from_private_key_string(private_key: &str) -> Result<Self, SignerError> {
        let keypair = KeypairUtil::from_private_key_string(private_key)?;
        Ok(Self::new(keypair))
    }

    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        Ok(keypair_sign_message(&self.keypair, serialized))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for MemorySigner {
    fn pubkey(&self) -> Pubkey {
        keypair_pubkey(&self.keypair)
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&tx.message_data()).await?;

        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey(), signature)?;

        Ok((TransactionUtil::serialize_transaction(tx)?, signature))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn sign_partial_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&tx.message_data()).await?;

        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey(), signature)?;

        Ok((TransactionUtil::serialize_transaction(tx)?, signature))
    }

    async fn is_available(&self) -> bool {
        // Memory signer is always available
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::create_test_transaction;

    use super::*;

    const TEST_KEYPAIR_BYTES: &str = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]";
    const TEST_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

    fn create_test_signer() -> MemorySigner {
        MemorySigner::from_private_key_string(TEST_KEYPAIR_BYTES)
            .expect("Failed to create test signer")
    }

    #[test]
    fn test_create_from_u8_array() {
        let signer = MemorySigner::from_private_key_string(TEST_KEYPAIR_BYTES);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_pubkey() {
        let signer = create_test_signer();
        let pubkey = signer.pubkey();
        assert_eq!(pubkey.to_string(), TEST_PUBKEY);
    }

    #[tokio::test]
    async fn test_sign_message() {
        let signer = create_test_signer();
        let message = b"Hello Solana!";
        let signature = signer.sign_message(message).await;

        assert!(signature.is_ok());
        let sig = signature.unwrap();
        // Solana signatures are 64 bytes
        assert_eq!(sig.as_ref().len(), 64);
    }

    #[tokio::test]
    async fn test_is_available() {
        let signer = create_test_signer();
        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        let signer = create_test_signer();

        let mut tx = create_test_transaction(&keypair_pubkey(&signer.keypair));

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());

        let (serialized_tx, signature) = result.unwrap();

        // Verify the signature is valid
        assert_eq!(signature.as_ref().len(), 64);

        // Verify the transaction is properly serialized
        assert!(!serialized_tx.is_empty());

        // Verify the transaction has the signature
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0], signature);
    }

    #[tokio::test]
    async fn test_sign_partial_transaction() {
        let signer = create_test_signer();

        let mut tx = create_test_transaction(&keypair_pubkey(&signer.keypair));

        let result = signer.sign_partial_transaction(&mut tx).await;
        assert!(result.is_ok());

        let (serialized_tx, signature) = result.unwrap();

        // Verify the signature is valid
        assert_eq!(signature.as_ref().len(), 64);

        // Verify the transaction is properly serialized
        assert!(!serialized_tx.is_empty());

        // Verify the transaction has the signature
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0], signature);
    }
}
