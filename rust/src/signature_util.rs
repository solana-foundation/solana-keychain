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
