//! Shared wallet-authentication JWT builder for backends that sign requests
//! with an ES256 `X-Wallet-Auth`-style header (CDP, Openfort).

use crate::error::SignerError;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Serialize)]
struct WalletClaims {
    uris: Vec<String>,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    #[serde(rename = "reqHash", skip_serializing_if = "Option::is_none")]
    req_hash: Option<String>,
}

/// Build the URI claim value for a JWT.
pub(crate) fn jwt_uri(host: &str, method: &str, path: &str) -> String {
    format!("{method} {host}{path}")
}

/// Extract request host (including port if present) from a base URL.
pub(crate) fn extract_host(base_url: &str, provider: &str) -> Result<String, SignerError> {
    let url = reqwest::Url::parse(base_url).map_err(|_| {
        SignerError::ConfigError(format!("Invalid {provider} base URL: {base_url}"))
    })?;

    let host = url.host_str().ok_or_else(|| {
        SignerError::ConfigError(format!("Missing host in {provider} base URL: {base_url}"))
    })?;

    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Recursively sort JSON object keys for deterministic hashing.
fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), sort_json(value));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        _ => value.clone(),
    }
}

/// Compute the request body hash for wallet authentication, if required.
pub(crate) fn compute_req_hash(body: Option<&Value>) -> Result<Option<String>, SignerError> {
    let body = match body {
        Some(body) => body,
        None => return Ok(None),
    };

    if body.is_null() {
        return Ok(None);
    }

    if matches!(body, Value::Object(map) if map.is_empty()) {
        return Ok(None);
    }

    let sorted = sort_json(body);
    let json = serde_json::to_string(&sorted).map_err(|e| {
        SignerError::SerializationError(format!("Failed to serialize request body: {e}"))
    })?;

    let hash = Sha256::digest(json.as_bytes());
    Ok(Some(hex::encode(hash)))
}

/// Create an ES256 wallet-authentication JWT over the request URI and body.
pub(crate) fn create_wallet_jwt(
    provider: &str,
    key: &EncodingKey,
    host: &str,
    method: &str,
    path: &str,
    request_body: Option<&Value>,
    lifetime_secs: i64,
) -> Result<String, SignerError> {
    let now = chrono::Utc::now().timestamp();

    let claims = WalletClaims {
        uris: vec![jwt_uri(host, method, path)],
        iat: now,
        nbf: now,
        exp: now + lifetime_secs,
        jti: Uuid::new_v4().to_string(),
        req_hash: compute_req_hash(request_body)?,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());

    encode(&header, &claims, key).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to encode wallet JWT: {_e}");
        SignerError::SigningFailed(format!("Failed to create {provider} wallet JWT"))
    })
}

#[cfg(test)]
mod tests;
