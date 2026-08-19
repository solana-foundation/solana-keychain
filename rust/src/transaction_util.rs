use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use base64::{engine::general_purpose::STANDARD, Engine};

/// A UUID derived from SHA-256(message bytes), so a retry of the same bytes
/// reuses the key and the provider deduplicates the create.
#[cfg(any(feature = "crossmint", feature = "fordefi"))]
pub(crate) fn idempotency_key_from_message(message_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(message_bytes);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key[6] = (key[6] & 0x0f) | 0x40;
    key[8] = (key[8] & 0x3f) | 0x80;
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

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

    /// Returns true when all required signature slots are populated with non-default values.
    pub fn has_all_required_signatures(transaction: &Transaction) -> bool {
        let num_required_signatures = transaction.message.header.num_required_signatures as usize;
        if transaction.signatures.len() < num_required_signatures {
            return false;
        }

        transaction
            .signatures
            .iter()
            .take(num_required_signatures)
            .all(|sig| *sig != Signature::default())
    }

    /// Classify a signed transaction result based on whether all required signatures are present.
    pub fn classify_signed_transaction(
        transaction: &Transaction,
        signed_transaction: SignedTransaction,
    ) -> SignTransactionResult {
        if Self::has_all_required_signatures(transaction) {
            SignTransactionResult::Complete(signed_transaction)
        } else {
            SignTransactionResult::Partial(signed_transaction)
        }
    }
}
