use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use base64::{engine::general_purpose::STANDARD, Engine};

pub struct TransactionUtil;

impl TransactionUtil {
    /// Encodes a Transaction to a base64 serialized String
    pub fn serialize_transaction(transaction: &Transaction) -> Result<String, SignerError> {
        Ok(
            STANDARD.encode(bincode::serialize(transaction).map_err(|e| {
                SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
            })?),
        )
    }

    /// Get the position of a pubkey in the transaction's signing keypair positions.
    /// Returns the index where this signer's signature should be placed.
    pub fn get_signing_keypair_position(
        transaction: &Transaction,
        pubkey: &Pubkey,
    ) -> Result<usize, SignerError> {
        let num_required_signatures = transaction.message.header.num_required_signatures as usize;

        if transaction.message.account_keys.len() < num_required_signatures {
            return Err(SignerError::SigningFailed(
                "Invalid account index: not enough account keys".to_string(),
            ));
        }

        let signed_keys = &transaction.message.account_keys[0..num_required_signatures];

        signed_keys.iter().position(|x| x == pubkey).ok_or_else(|| {
            SignerError::SigningFailed(format!(
                "Pubkey {} not found in transaction signers",
                pubkey
            ))
        })
    }

    /// Add a signature to the transaction at the correct position.
    pub fn add_signature_to_transaction(
        transaction: &mut Transaction,
        pubkey: &Pubkey,
        signature: Signature,
    ) -> Result<(), SignerError> {
        let position = Self::get_signing_keypair_position(transaction, pubkey)?;

        // Ensure signatures vec is large enough
        let num_required_signatures = transaction.message.header.num_required_signatures as usize;
        if transaction.signatures.len() < num_required_signatures {
            transaction
                .signatures
                .resize(num_required_signatures, Signature::default());
        }

        // Place signature at the correct position
        transaction.signatures[position] = signature;

        Ok(())
    }
}
