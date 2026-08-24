use crate::error::SignerError;
use crate::sdk_adapter::{keypair_from_seed, keypair_pubkey};
use crate::wallet_jwt;
use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// PKCS#8 DER prefix for Ed25519 private keys.
/// Structure: SEQUENCE { INTEGER 0, SEQUENCE { OID Ed25519 }, OCTET STRING { OCTET STRING { seed } } }
const ED25519_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

// ─── JWT Types ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuthClaims {
    sub: String,
    iss: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    uris: Vec<String>,
}

/// Wraps raw DER bytes as a PKCS#8 PEM string (-----BEGIN PRIVATE KEY-----).
pub(super) fn der_to_pkcs8_pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let wrapped = b64
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----\n")
}

/// Validate a base64-encoded Ed25519 key (seed || pubkey).
fn validate_ed25519_keypair_bytes(key_bytes: &[u8]) -> Result<(), SignerError> {
    if key_bytes.len() != 64 {
        return Err(SignerError::InvalidPrivateKey(format!(
            "Invalid Ed25519 key length: expected 64 bytes, got {}",
            key_bytes.len()
        )));
    }

    let seed = &key_bytes[..32];
    let provided_pubkey = &key_bytes[32..];

    let keypair = keypair_from_seed(seed).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to derive Ed25519 keypair from seed: {_e}");
        SignerError::InvalidPrivateKey("Invalid Ed25519 seed".to_string())
    })?;

    let derived_pubkey = keypair_pubkey(&keypair).to_bytes();
    if derived_pubkey.as_ref() != provided_pubkey {
        return Err(SignerError::InvalidPrivateKey(
            "Ed25519 public key does not match seed".to_string(),
        ));
    }

    Ok(())
}

/// Generate a random nonce for JWT header fields.
fn random_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Create the main CDP API authentication JWT.
///
/// Supports Ed25519 keys (base64-encoded, 64 bytes: seed || pubkey).
///
/// The CDP API expects a `nonce` field in the JWT protected header for replay prevention.
pub(super) fn create_auth_jwt(
    api_key_id: &str,
    api_key_secret: &str,
    host: &str,
    method: &str,
    path: &str,
) -> Result<String, SignerError> {
    let now = chrono::Utc::now().timestamp();

    let claims = AuthClaims {
        sub: api_key_id.to_string(),
        iss: "cdp".to_string(),
        iat: now,
        nbf: now,
        exp: now + 120,
        uris: vec![wallet_jwt::jwt_uri(host, method, path)],
    };

    if api_key_secret.starts_with("-----BEGIN") {
        return Err(SignerError::InvalidPrivateKey(
            "PEM EC keys are not supported; use base64 Ed25519 key".to_string(),
        ));
    }

    // Base64-encoded Ed25519 key (64 bytes: seed || pubkey)
    let key_bytes = STANDARD.decode(api_key_secret).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to base64-decode Ed25519 key: {_e}");
        SignerError::InvalidPrivateKey(
            "Failed to decode Ed25519 private key from base64".to_string(),
        )
    })?;

    validate_ed25519_keypair_bytes(&key_bytes)?;

    // Build PKCS#8 DER from seed (first 32 bytes)
    let seed = &key_bytes[..32];
    let mut der = ED25519_PKCS8_PREFIX.to_vec();
    der.extend_from_slice(seed);
    let pem = der_to_pkcs8_pem(&der);

    let key = EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to create Ed25519 encoding key: {_e}");
        SignerError::InvalidPrivateKey("Failed to create Ed25519 key for JWT signing".to_string())
    })?;
    let alg = Algorithm::EdDSA;

    let mut header = Header::new(alg);
    header.kid = Some(api_key_id.to_string());
    header.typ = Some("JWT".to_string());
    header.nonce = Some(random_nonce());

    encode(&header, &claims, &key).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to encode JWT: {_e}");
        SignerError::SigningFailed("Failed to create CDP authentication JWT".to_string())
    })
}

/// Create the CDP wallet authentication JWT (X-Wallet-Auth header).
///
/// Required for signing endpoints (POST /accounts/.../sign/*).
/// The wallet secret is a base64-encoded PKCS#8 DER EC (P-256) private key.
pub(super) fn create_wallet_jwt(
    wallet_secret: &str,
    host: &str,
    method: &str,
    path: &str,
    request_body: Option<&Value>,
) -> Result<String, SignerError> {
    // The wallet secret is base64-encoded PKCS#8 DER (P-256)
    let der_bytes = STANDARD.decode(wallet_secret).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to decode walletSecret from base64: {_e}");
        SignerError::InvalidPrivateKey("Failed to decode walletSecret from base64".to_string())
    })?;

    let pem = der_to_pkcs8_pem(&der_bytes);

    let key = EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse wallet EC key: {_e}");
        SignerError::InvalidPrivateKey("Failed to parse walletSecret as EC private key".to_string())
    })?;

    wallet_jwt::create_wallet_jwt("CDP", &key, host, method, path, request_body)
}
