//! Shared helpers for decoding and verifying Ed25519 signatures returned by
//! signer backends.

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature};

pub const EXPECTED_SIGNATURE_LENGTH: usize = 64;

/// Convert raw bytes into a [`Signature`], rejecting any length other than 64.
pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature, SignerError> {
    let sig_array: [u8; EXPECTED_SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| {
        SignerError::SigningFailed(format!(
            "Invalid signature length: expected {EXPECTED_SIGNATURE_LENGTH} bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(Signature::from(sig_array))
}

/// Decode a base58-encoded signature.
pub fn signature_from_base58(encoded: &str) -> Result<Signature, SignerError> {
    let bytes = bs58::decode(encoded).into_vec().map_err(|_| {
        SignerError::SerializationError("Failed to decode base58 signature".to_string())
    })?;
    signature_from_bytes(&bytes)
}

/// Decode a base64-encoded signature.
pub fn signature_from_base64(encoded: &str) -> Result<Signature, SignerError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD.decode(encoded).map_err(|_| {
        SignerError::SerializationError("Failed to decode base64 signature".to_string())
    })?;
    signature_from_bytes(&bytes)
}

/// Decode a hex-encoded signature, with or without a `0x` prefix.
#[cfg(any(
    feature = "fireblocks",
    feature = "turnkey",
    feature = "para",
    feature = "dfns",
    feature = "openfort"
))]
pub fn signature_from_hex(encoded: &str) -> Result<Signature, SignerError> {
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    let bytes = hex::decode(encoded).map_err(|_| {
        SignerError::SerializationError("Failed to decode hex signature".to_string())
    })?;
    signature_from_bytes(&bytes)
}

/// Locate this signer's signature by its required-signer position, rejecting a
/// missing or default signature in that slot.
#[cfg(any(
    feature = "privy",
    feature = "turnkey",
    feature = "cdp",
    feature = "utila",
    feature = "fordefi"
))]
fn signature_at_signer_position(
    transaction: &crate::sdk_adapter::VersionedTransaction,
    public_key: &Pubkey,
) -> Result<Signature, SignerError> {
    let position = crate::transaction_util::TransactionUtil::get_signing_keypair_position(
        transaction,
        public_key,
    )?;
    transaction
        .signatures
        .get(position)
        .copied()
        .filter(|signature| *signature != Signature::default())
        .ok_or_else(|| {
            SignerError::SigningFailed(
                "Returned signed transaction is missing the signer's signature".to_string(),
            )
        })
}

/// Extract and verify this signer's signature from a fully-signed transaction
/// returned by a provider that signed the bytes we submitted.
///
/// Verifying against `original_message_bytes` guarantees the signature applies
/// to the transaction we submitted, so no byte-equality check of the returned
/// message is needed.
#[cfg(any(
    feature = "privy",
    feature = "turnkey",
    feature = "cdp",
    feature = "utila"
))]
pub(crate) fn extract_and_verify_returned_signature(
    returned_tx_bytes: &[u8],
    public_key: &Pubkey,
    original_message_bytes: &[u8],
) -> Result<Signature, SignerError> {
    let returned = crate::transaction_util::deserialize_wire_transaction(returned_tx_bytes)?;
    let signature = signature_at_signer_position(&returned, public_key)?;
    verify_or_reject(&signature, public_key, original_message_bytes)?;
    Ok(signature)
}

/// Verify this signer's signature against the message the returned transaction
/// carries, for a provider that rewrote the message before signing it.
///
/// Both are handed back: the caller has to continue from these bytes, not from
/// the ones it submitted.
#[cfg(feature = "fordefi")]
pub(crate) fn extract_and_verify_rewritten_transaction(
    returned_tx_bytes: &[u8],
    public_key: &Pubkey,
) -> Result<(crate::sdk_adapter::VersionedTransaction, Signature), SignerError> {
    let returned = crate::transaction_util::deserialize_wire_transaction(returned_tx_bytes)?;
    let signature = signature_at_signer_position(&returned, public_key)?;
    verify_or_reject(&signature, public_key, &returned.message.serialize())?;
    Ok((returned, signature))
}

/// Reject a backend-returned signature that does not verify against the
/// signer's public key over the signed bytes.
pub fn verify_or_reject(
    signature: &Signature,
    public_key: &Pubkey,
    message: &[u8],
) -> Result<(), SignerError> {
    if signature.verify(&public_key.to_bytes(), message) {
        return Ok(());
    }
    Err(SignerError::SigningFailed(
        "Signature verification failed — the returned signature does not match the public key"
            .to_string(),
    ))
}

#[cfg(all(
    test,
    any(
        feature = "privy",
        feature = "turnkey",
        feature = "cdp",
        feature = "utila"
    )
))]
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
    use crate::test_util::create_test_transaction;
    use crate::transaction_util::serialize_wire_transaction;

    fn signed_returned_transaction() -> (Keypair, Pubkey, Vec<u8>, Vec<u8>) {
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);
        let mut transaction = create_test_transaction(&pubkey);
        let message_bytes = transaction.message.serialize();
        let signature = keypair_sign_message(&keypair, &message_bytes);
        transaction.signatures = vec![signature];
        let wire = serialize_wire_transaction(&transaction).expect("serialize");
        (keypair, pubkey, message_bytes, wire)
    }

    #[test]
    fn extracts_and_verifies_a_valid_returned_signature() {
        let (keypair, pubkey, message_bytes, wire) = signed_returned_transaction();
        let expected = keypair_sign_message(&keypair, &message_bytes);

        let signature = extract_and_verify_returned_signature(&wire, &pubkey, &message_bytes)
            .expect("valid signature should be extracted");

        assert_eq!(signature, expected);
    }

    #[test]
    fn rejects_a_pubkey_that_is_not_a_required_signer() {
        let (_keypair, _pubkey, message_bytes, wire) = signed_returned_transaction();
        let other = Pubkey::new_unique();

        let error = extract_and_verify_returned_signature(&wire, &other, &message_bytes)
            .expect_err("non-signer pubkey must be rejected");

        assert!(matches!(error, SignerError::SigningFailed(_)));
    }

    #[test]
    fn rejects_a_default_signature_in_the_signer_slot() {
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);
        let transaction = create_test_transaction(&pubkey);
        let message_bytes = transaction.message.serialize();
        let wire = serialize_wire_transaction(&transaction).expect("serialize");

        let error = extract_and_verify_returned_signature(&wire, &pubkey, &message_bytes)
            .expect_err("default signature must be rejected");

        assert!(matches!(error, SignerError::SigningFailed(_)));
    }

    #[test]
    fn rejects_a_signature_that_does_not_verify() {
        let (keypair, pubkey, message_bytes, _wire) = signed_returned_transaction();
        let mut transaction = create_test_transaction(&pubkey);
        transaction.signatures = vec![keypair_sign_message(&keypair, b"different bytes")];
        let wire = serialize_wire_transaction(&transaction).expect("serialize");

        let error = extract_and_verify_returned_signature(&wire, &pubkey, &message_bytes)
            .expect_err("non-verifying signature must be rejected");

        assert!(matches!(error, SignerError::SigningFailed(_)));
    }

    #[test]
    fn rejects_malformed_transaction_bytes() {
        let pubkey = Pubkey::new_unique();

        let error = extract_and_verify_returned_signature(&[0xff, 0x01, 0x02], &pubkey, b"msg")
            .expect_err("malformed bytes must be rejected");

        assert!(matches!(error, SignerError::SerializationError(_)));
    }
}
