//! Fireblocks JWT authentication helper

use crate::error::SignerError;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const JWT_TTL_SECS: i64 = 120;
const JWT_SKEW_LEEWAY_SECS: i64 = 60;

#[derive(Serialize)]
struct FireblocksClaims {
    uri: String,
    nonce: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    sub: String,
    #[serde(rename = "bodyHash")]
    body_hash: String,
}

/// Create a JWT for Fireblocks API authentication
///
/// # Arguments
///
/// * `api_key` - Fireblocks API key (used as subject)
/// * `encoding_key` - Parsed RSA encoding key
/// * `uri` - API endpoint path (e.g., "/v1/transactions")
/// * `body` - Request body as string (empty string for GET requests)
pub fn create_jwt(
    api_key: &str,
    encoding_key: &EncodingKey,
    uri: &str,
    body: &str,
) -> Result<String, SignerError> {
    let now = chrono::Utc::now().timestamp();
    let issued_at = now - JWT_SKEW_LEEWAY_SECS;

    // SHA256 hash of body
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let body_hash = hex::encode(hasher.finalize());

    let claims = FireblocksClaims {
        uri: uri.to_string(),
        nonce: Uuid::new_v4().to_string(),
        iat: issued_at,
        nbf: issued_at,
        exp: now + JWT_TTL_SECS,
        sub: api_key.to_string(),
        body_hash,
    };

    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, encoding_key).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to create JWT: {_e}");

        SignerError::SigningFailed("Failed to create JWT".to_string())
    })
}

/// Parse a Fireblocks RSA private key once for token reuse.
pub fn parse_encoding_key(private_key_pem: &str) -> Result<EncodingKey, SignerError> {
    EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse RSA key: {_e}");

        SignerError::InvalidPrivateKey("Failed to parse RSA key".to_string())
    })
}

#[cfg(test)]
mod tests;
