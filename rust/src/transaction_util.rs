use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
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

/// A 4xx is the only create outcome that rules out a transaction; anything else
/// (no response, timeout, 5xx, unusable success body) may already be executing.
/// `status` is `None` when no response arrived, and is reported back to the caller
/// only when the response itself was the failure.
#[cfg(any(feature = "crossmint", feature = "fordefi"))]
pub(crate) fn unconfirmed_unless_rejected(status: Option<u16>, error: SignerError) -> SignerError {
    if matches!(status, Some(status) if (400..500).contains(&status)) {
        return error;
    }
    SignerError::BroadcastUnconfirmed {
        provider_tx_id: None,
        provider_status: status.filter(|status| *status >= 400),
        detail: error.detail_string(),
    }
}

/// Serialize a transaction to canonical wire bytes.
#[cfg(feature = "sdk-v4")]
pub(crate) fn serialize_wire_transaction(
    transaction: &VersionedTransaction,
) -> Result<Vec<u8>, SignerError> {
    wincode::serialize(transaction).map_err(|e| {
        SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
    })
}

#[cfg(not(feature = "sdk-v4"))]
pub(crate) fn serialize_wire_transaction(
    transaction: &VersionedTransaction,
) -> Result<Vec<u8>, SignerError> {
    bincode::serialize(transaction).map_err(|e| {
        SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
    })
}

/// Deserialize canonical wire bytes.
#[cfg(feature = "sdk-v4")]
pub(crate) fn deserialize_wire_transaction(
    bytes: &[u8],
) -> Result<VersionedTransaction, SignerError> {
    wincode::deserialize(bytes).map_err(|e| {
        SignerError::SerializationError(format!("Failed to deserialize transaction: {e}"))
    })
}

#[cfg(not(feature = "sdk-v4"))]
pub(crate) fn deserialize_wire_transaction(
    bytes: &[u8],
) -> Result<VersionedTransaction, SignerError> {
    bincode::deserialize(bytes).map_err(|e| {
        SignerError::SerializationError(format!("Failed to deserialize transaction: {e}"))
    })
}

pub struct TransactionUtil;

impl TransactionUtil {
    /// Encodes a Transaction to a base64 serialized String
    pub fn serialize_transaction(
        transaction: &VersionedTransaction,
    ) -> Result<String, SignerError> {
        Ok(STANDARD.encode(serialize_wire_transaction(transaction)?))
    }

    /// Get the position of a pubkey in the transaction's signing keypair positions.
    /// Returns the index where this signer's signature should be placed.
    pub fn get_signing_keypair_position(
        transaction: &VersionedTransaction,
        pubkey: &Pubkey,
    ) -> Result<usize, SignerError> {
        let num_required_signatures = transaction.message.header().num_required_signatures as usize;

        if transaction.message.static_account_keys().len() < num_required_signatures {
            return Err(SignerError::SigningFailed(
                "Invalid account index: not enough account keys".to_string(),
            ));
        }

        let signed_keys = &transaction.message.static_account_keys()[0..num_required_signatures];

        signed_keys.iter().position(|x| x == pubkey).ok_or_else(|| {
            SignerError::SigningFailed(format!(
                "Pubkey {} not found in transaction signers",
                pubkey
            ))
        })
    }

    /// Add a signature to the transaction at the correct position.
    pub fn add_signature_to_transaction(
        transaction: &mut VersionedTransaction,
        pubkey: &Pubkey,
        signature: Signature,
    ) -> Result<(), SignerError> {
        let position = Self::get_signing_keypair_position(transaction, pubkey)?;

        // Ensure signatures vec is large enough
        let num_required_signatures = transaction.message.header().num_required_signatures as usize;
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
    pub fn has_all_required_signatures(transaction: &VersionedTransaction) -> bool {
        let num_required_signatures = transaction.message.header().num_required_signatures as usize;
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
        transaction: &VersionedTransaction,
        signed_transaction: SignedTransaction,
    ) -> SignTransactionResult {
        if Self::has_all_required_signatures(transaction) {
            SignTransactionResult::Complete(signed_transaction)
        } else {
            SignTransactionResult::Partial(signed_transaction)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "sdk-v4")]
    use super::*;
    #[cfg(feature = "sdk-v4")]
    use crate::test_util::{create_test_transaction, create_test_v1_transaction};

    #[cfg(feature = "sdk-v4")]
    #[test]
    fn wincode_matches_bincode_for_a_legacy_transaction() {
        let transaction = create_test_transaction(&Pubkey::new_unique());

        let wire = serialize_wire_transaction(&transaction).expect("serialize");
        let bincode_wire = bincode::serialize(&transaction).expect("bincode serialize");

        assert_eq!(wire, bincode_wire);
    }

    #[cfg(feature = "sdk-v4")]
    #[test]
    fn v1_envelope_places_the_message_first_and_signatures_last() {
        let transaction = create_test_v1_transaction(&Pubkey::new_unique());
        let message_bytes = transaction.message.serialize();

        let wire = serialize_wire_transaction(&transaction).expect("serialize");

        assert_eq!(message_bytes[0], 0x81);
        assert_eq!(wire[..message_bytes.len()], message_bytes[..]);
        assert_eq!(wire.len(), message_bytes.len() + 64);
        assert_ne!(wire, bincode::serialize(&transaction).expect("bincode"));
    }

    #[cfg(feature = "sdk-v4")]
    #[test]
    fn v1_wire_transaction_round_trips() {
        let transaction = create_test_v1_transaction(&Pubkey::new_unique());
        let wire = serialize_wire_transaction(&transaction).expect("serialize");

        let decoded = deserialize_wire_transaction(&wire).expect("deserialize");

        assert_eq!(decoded.message.serialize(), transaction.message.serialize());
        assert_eq!(decoded.signatures, transaction.signatures);
    }
}
