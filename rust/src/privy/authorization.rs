use crate::error::SignerError;
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type PrivyAuthorizationSignFn = Arc<dyn Fn(&[u8]) -> Result<String, SignerError> + Send + Sync>;

pub type PrivyAuthorizationContextProvider = Arc<
    dyn Fn(
            &PrivyAuthorizationRequestInput,
        ) -> Result<Option<PrivyAuthorizationContext>, SignerError>
        + Send
        + Sync,
>;

#[derive(Clone, Default)]
pub struct PrivyAuthorizationContext {
    /// Base64-encoded PKCS8 P-256 private keys exported by Privy.
    /// `wallet-auth:` and `wallet-api:` prefixes are accepted.
    pub authorization_private_keys: Vec<String>,
    /// Precomputed base64 authorization signatures for this exact request.
    pub signatures: Vec<String>,
    /// External signers that receive the exact canonical payload bytes.
    pub sign_fns: Vec<PrivyAuthorizationSignFn>,
}

#[derive(Clone)]
pub enum PrivyAuthorizationConfig {
    Context(PrivyAuthorizationContext),
    Provider(PrivyAuthorizationContextProvider),
}

impl From<PrivyAuthorizationContext> for PrivyAuthorizationConfig {
    fn from(value: PrivyAuthorizationContext) -> Self {
        Self::Context(value)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PrivyAuthorizationRequestInput {
    pub version: u8,
    pub method: String,
    pub url: String,
    pub body: Value,
    pub headers: BTreeMap<String, String>,
}

#[derive(Default)]
pub(super) struct PrivyAuthorizationHeaders {
    pub authorization_signature: Option<String>,
    pub request_expiry: Option<String>,
}

const DEFAULT_PRIVY_AUTHORIZATION_REQUEST_EXPIRY_MS: u64 = 15 * 60 * 1000;

pub fn default_privy_authorization_request_expiry_ms() -> u64 {
    DEFAULT_PRIVY_AUTHORIZATION_REQUEST_EXPIRY_MS
}

pub(super) fn prepare_privy_authorization_headers<T: Serialize>(
    app_id: &str,
    authorization_config: Option<&PrivyAuthorizationConfig>,
    method: &str,
    url: &str,
    body: &T,
    request_expiry_ms: Option<u64>,
) -> Result<PrivyAuthorizationHeaders, SignerError> {
    let Some(authorization_config) = authorization_config else {
        return Ok(PrivyAuthorizationHeaders::default());
    };

    let request_expiry = request_expiry_ms
        .map(|expiry_ms| current_time_millis().map(|now| (now + expiry_ms).to_string()))
        .transpose()?;

    let mut headers = BTreeMap::new();
    headers.insert("privy-app-id".to_string(), app_id.to_string());
    if let Some(request_expiry) = &request_expiry {
        headers.insert("privy-request-expiry".to_string(), request_expiry.clone());
    }

    let request = PrivyAuthorizationRequestInput {
        version: 1,
        method: method.to_string(),
        url: url.to_string(),
        body: serde_json::to_value(body)?,
        headers,
    };

    let context = match authorization_config {
        PrivyAuthorizationConfig::Context(context) => Some(context.clone()),
        PrivyAuthorizationConfig::Provider(provider) => provider(&request)?,
    };

    let Some(context) = context else {
        return Ok(PrivyAuthorizationHeaders::default());
    };

    let signatures = generate_privy_authorization_signatures(&request, &context)?;
    if signatures.is_empty() {
        return Err(SignerError::ConfigError(
            "authorization_context must include authorization_private_keys, signatures, or sign_fns"
                .to_string(),
        ));
    }

    Ok(PrivyAuthorizationHeaders {
        authorization_signature: Some(signatures.join(",")),
        request_expiry,
    })
}

pub fn generate_privy_authorization_signatures(
    request: &PrivyAuthorizationRequestInput,
    authorization_context: &PrivyAuthorizationContext,
) -> Result<Vec<String>, SignerError> {
    let payload = format_privy_authorization_signature_payload(request)?;
    let mut signatures = authorization_context.signatures.clone();

    for private_key in &authorization_context.authorization_private_keys {
        signatures.push(generate_privy_authorization_signature(
            private_key,
            &payload,
        )?);
    }

    for sign_fn in &authorization_context.sign_fns {
        signatures.push(sign_fn(&payload)?);
    }

    Ok(signatures)
}

pub fn format_privy_authorization_signature_payload(
    request: &PrivyAuthorizationRequestInput,
) -> Result<Vec<u8>, SignerError> {
    let mut value = serde_json::to_value(request)?;

    if let Some(body) = value.get_mut("body") {
        if body.as_object().is_some_and(|body| body.is_empty()) {
            *body = Value::String(String::new());
        }
    }

    canonicalize_json(&value)
        .map(|serialized| serialized.into_bytes())
        .ok_or_else(|| {
            SignerError::SerializationError(
                "Failed to serialize Privy authorization request".to_string(),
            )
        })
}

fn generate_privy_authorization_signature(
    authorization_private_key: &str,
    payload: &[u8],
) -> Result<String, SignerError> {
    let signing_key = parse_p256_private_key(authorization_private_key)?;
    let signature: p256::ecdsa::Signature = signing_key.sign(payload);
    Ok(STANDARD.encode(signature.to_der().as_bytes()))
}

fn parse_p256_private_key(
    authorization_private_key: &str,
) -> Result<p256::ecdsa::SigningKey, SignerError> {
    let normalized = authorization_private_key
        .strip_prefix("wallet-auth:")
        .or_else(|| authorization_private_key.strip_prefix("wallet-api:"))
        .unwrap_or(authorization_private_key)
        .trim();

    if normalized.contains("-----BEGIN") {
        let pem = normalized.replace("\\n", "\n");
        return p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("Invalid Privy authorization private key: {e}"))
        });
    }

    let compact = normalized.split_whitespace().collect::<String>();
    let der = STANDARD.decode(compact).map_err(|e| {
        SignerError::InvalidPrivateKey(format!(
            "Invalid Privy authorization private key encoding: {e}"
        ))
    })?;

    p256::ecdsa::SigningKey::from_pkcs8_der(&der).map_err(|e| {
        SignerError::InvalidPrivateKey(format!("Invalid Privy authorization private key: {e}"))
    })
}

fn canonicalize_json(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) => serde_json::to_string(value).ok(),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonicalize_json)
                .collect::<Option<Vec<_>>>()?;
            Some(format!("[{}]", values.join(",")))
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key).ok()?;
                    let value = canonicalize_json(value)?;
                    Some(format!("{key}:{value}"))
                })
                .collect::<Option<Vec<_>>>()?;
            Some(format!("{{{}}}", entries.join(",")))
        }
    }
}

fn current_time_millis() -> Result<u64, SignerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
        SignerError::SigningFailed(format!("Failed to compute Privy request expiry: {e}"))
    })?;

    Ok(duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;

    const TEST_P256_PKCS8_PEM: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n",
        "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n",
        "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n",
        "-----END PRIVATE KEY-----"
    );
    const TEST_P256_PKCS8_BASE64: &str = concat!(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG",
        "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY",
        "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf"
    );

    fn authorization_request(body: Value) -> PrivyAuthorizationRequestInput {
        PrivyAuthorizationRequestInput {
            version: 1,
            method: "POST".to_string(),
            url: "https://api.privy.test/wallets/test-wallet-id/rpc".to_string(),
            body,
            headers: BTreeMap::from([
                ("privy-app-id".to_string(), "test-app-id".to_string()),
                ("privy-request-expiry".to_string(), "1900000".to_string()),
            ]),
        }
    }

    #[test]
    fn formats_empty_authorization_request_bodies_like_privy_sdk() {
        let request = authorization_request(serde_json::json!({}));

        let payload = format_privy_authorization_signature_payload(&request).unwrap();

        assert_eq!(
            String::from_utf8(payload).unwrap(),
            "{\"body\":\"\",\"headers\":{\"privy-app-id\":\"test-app-id\",\"privy-request-expiry\":\"1900000\"},\"method\":\"POST\",\"url\":\"https://api.privy.test/wallets/test-wallet-id/rpc\",\"version\":1}"
        );
    }

    #[test]
    fn generates_base64_der_authorization_signatures_from_privy_private_keys() {
        let request = authorization_request(serde_json::json!({
            "chain_type": "solana",
            "method": "signMessage",
            "params": {
                "encoding": "base64",
                "message": "AQIDBA=="
            }
        }));
        let context = PrivyAuthorizationContext {
            authorization_private_keys: vec![format!("wallet-auth:{TEST_P256_PKCS8_BASE64}")],
            ..Default::default()
        };

        let signatures = generate_privy_authorization_signatures(&request, &context).unwrap();
        let payload = format_privy_authorization_signature_payload(&request).unwrap();
        let signature_bytes = STANDARD.decode(&signatures[0]).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&signature_bytes).unwrap();
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(TEST_P256_PKCS8_PEM).unwrap();

        signing_key
            .verifying_key()
            .verify(&payload, &signature)
            .unwrap();
    }

    #[test]
    fn preserves_privy_signature_order() {
        let request = authorization_request(serde_json::json!({"method": "signMessage"}));
        let context = PrivyAuthorizationContext {
            signatures: vec!["provided".to_string()],
            sign_fns: vec![Arc::new(|_| Ok("sign-fn".to_string()))],
            ..Default::default()
        };

        let signatures = generate_privy_authorization_signatures(&request, &context).unwrap();

        assert_eq!(signatures, vec!["provided", "sign-fn"]);
    }
}
