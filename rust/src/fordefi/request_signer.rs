//! Pluggable API-request signer for Fordefi.
//!
//! Fordefi authenticates every POST with a request-level signature over
//! `{path}|{timestamp}|{body}` (ECDSA P-256, SHA-256, DER, base64) sent in the
//! `x-signature` header. This is separate from the Solana Ed25519 signature that
//! Fordefi's MPC produces and returns.
//!
//! The [`FordefiRequestSigner`] trait abstracts that request-signing step so the
//! P-256 key does not have to be handed over as raw PEM material. The built-in
//! [`PemRequestSigner`] covers the common case; a custom implementation can keep
//! the key in a KMS/HSM (e.g. AWS KMS `Sign` with `ECDSA_SHA_256`, which already
//! returns a DER signature — just base64-encode it).

use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Signer as _, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;

use crate::error::SignerError;

/// Signs Fordefi API-request payloads for the `x-signature` header.
///
/// Implementations receive the fully-formatted payload (`{path}|{timestamp}|{body}`)
/// and must return the exact base64 value Fordefi expects: base64 of the
/// DER-encoded ECDSA P-256 signature over `SHA-256(payload)`.
///
/// The method is `async` so implementations backed by a KMS/HSM can perform
/// network calls; the built-in [`PemRequestSigner`] signs locally and ignores it.
#[async_trait::async_trait]
pub trait FordefiRequestSigner: Send + Sync {
    /// Sign `payload` and return the base64-encoded `x-signature` value.
    async fn sign_request(&self, payload: &[u8]) -> Result<String, SignerError>;
}

/// Built-in [`FordefiRequestSigner`] that signs locally with a PEM-encoded
/// ECDSA P-256 private key. This is the default used by
/// [`FordefiSigner::from_config`](super::FordefiSigner::from_config).
pub struct PemRequestSigner {
    signing_key: SigningKey,
}

impl PemRequestSigner {
    /// Parse an ECDSA P-256 private key from PEM format.
    /// Supports both PKCS#8 and SEC1 (EC) PEM encodings.
    pub fn from_pem(pem: &str) -> Result<Self, SignerError> {
        if let Ok(signing_key) = SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self { signing_key });
        }
        if let Ok(secret) = p256::SecretKey::from_sec1_pem(pem) {
            return Ok(Self {
                signing_key: SigningKey::from(secret),
            });
        }
        Err(SignerError::InvalidPrivateKey(
            "Failed to parse PEM as ECDSA P-256 key (tried PKCS#8 and SEC1)".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl FordefiRequestSigner for PemRequestSigner {
    async fn sign_request(&self, payload: &[u8]) -> Result<String, SignerError> {
        // p256 Signer::sign() performs SHA-256 hashing internally (ECDSA-SHA256).
        let signature: p256::ecdsa::Signature = self.signing_key.sign(payload);
        Ok(STANDARD.encode(signature.to_der()))
    }
}
