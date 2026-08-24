//! Openfort backend wallet signer.
//!
//! Signs Solana transactions and messages by calling Openfort's
//! `POST /v2/accounts/backend/{accountId}/sign` endpoint. The private key
//! lives in Openfort's TEE and is never exposed.
//!
//! # Authentication
//!
//! Each request requires two headers:
//! - `Authorization: Bearer <secret_key>` — Openfort project secret key
//!   (`sk_live_*` or `sk_test_*`).
//! - `x-wallet-auth: <ES256 JWT>` — JWT signed by the project's wallet secret
//!   (an ECDSA P-256 private key) issued by the Openfort dashboard.
//!
//! # Configuration
//!
//! The signer takes three inputs: project secret key, backend wallet account ID
//! (`acc_<uuid>`), and the wallet secret. The wallet secret may be either the
//! bare base64-encoded PKCS#8 DER body (the convenient single-line form for
//! env vars) or a full PEM string (`-----BEGIN PRIVATE KEY-----` ...). The
//! Solana address is fetched from `GET /v2/accounts/{account_id}` during
//! [`OpenfortSigner::init`].
//!
//! # Solana payload
//!
//! For SVM wallets, Openfort signs the bytes as-is (no hashing) and returns a
//! 64-byte ed25519 signature. The signer hex-encodes the message bytes, sends
//! them in the `data` field, then verifies the returned signature against the
//! address resolved at init time.

mod types;

use crate::remote_util::parse_json_response;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{signature_from_hex, verify_or_reject};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use uuid::Uuid;

use self::types::SignResponse;

const JWT_LIFETIME_SECS: i64 = 120;

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

/// Format the URI claim as `<METHOD> <HOST><PATH>`.
fn jwt_uri(host: &str, method: &str, path: &str) -> String {
    format!("{method} {host}{path}")
}

/// Extract host (with port if present) from a base URL.
fn extract_host(base_url: &str) -> Result<String, SignerError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| SignerError::ConfigError(format!("Invalid Openfort base URL: {base_url}")))?;

    let host = url.host_str().ok_or_else(|| {
        SignerError::ConfigError(format!("Missing host in Openfort base URL: {base_url}"))
    })?;

    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Recursively sort JSON object keys so the request hash is deterministic.
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

/// Compute hex(sha256(sorted-JSON(body))).
fn compute_req_hash(body: &Value) -> Result<String, SignerError> {
    let sorted = sort_json(body);
    let json = serde_json::to_string(&sorted).map_err(|e| {
        SignerError::SerializationError(format!("Failed to serialize request body: {e}"))
    })?;
    Ok(hex::encode(Sha256::digest(json.as_bytes())))
}

/// Normalize the wallet secret to a PEM string `jsonwebtoken` can parse.
/// Accepts either a full PEM (passed through verbatim) or a bare base64
/// PKCS#8 DER body (the convenient single-line form), in which case it
/// strips whitespace and wraps it in PEM headers.
fn wallet_secret_to_pem(wallet_secret: &str) -> String {
    if wallet_secret.trim_start().starts_with("-----BEGIN") {
        return wallet_secret.to_string();
    }

    let stripped: String = wallet_secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    format!("-----BEGIN PRIVATE KEY-----\n{stripped}\n-----END PRIVATE KEY-----\n")
}

/// Build the X-Wallet-Auth JWT for an Openfort backend wallet request.
fn create_wallet_jwt(
    wallet_secret: &str,
    host: &str,
    method: &str,
    path: &str,
    request_body: &Value,
) -> Result<String, SignerError> {
    let now = chrono::Utc::now().timestamp();

    let claims = WalletClaims {
        uris: vec![jwt_uri(host, method, path)],
        iat: now,
        nbf: now,
        exp: now + JWT_LIFETIME_SECS,
        jti: Uuid::new_v4().to_string(),
        req_hash: Some(compute_req_hash(request_body)?),
    };

    let pem = wallet_secret_to_pem(wallet_secret);
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse Openfort wallet secret as EC key: {_e}");
        SignerError::InvalidPrivateKey(
            "Failed to parse Openfort wallet secret as EC P-256 private key (expected base64 PKCS#8 DER or PEM)"
                .to_string(),
        )
    })?;

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("JWT".to_string());

    encode(&header, &claims, &key).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to encode Openfort wallet JWT: {_e}");
        SignerError::SigningFailed("Failed to create Openfort wallet JWT".to_string())
    })
}

const OPENFORT_API_HOST: &str = "api.openfort.io";
const OPENFORT_BACKEND_PATH: &str = "/v2/accounts/backend";
const OPENFORT_ACCOUNTS_PATH: &str = "/v2/accounts";

/// Configuration for an [`OpenfortSigner`].
#[derive(Clone)]
pub struct OpenfortSignerConfig {
    /// Project secret key (`sk_live_*` or `sk_test_*`).
    pub secret_key: String,
    /// Backend wallet account ID (`acc_<uuid>`).
    pub account_id: String,
    /// ECDSA P-256 PKCS#8 private key issued by the Openfort dashboard,
    /// used to sign the `x-wallet-auth` JWT. Accepts either the bare base64
    /// DER body (single-line, env-var-friendly) or a full PEM string.
    pub wallet_secret: String,
    /// Base URL (defaults to `https://api.openfort.io`).
    pub api_base_url: Option<String>,
    pub http_client_config: Option<HttpClientConfig>,
}

/// Openfort backend wallet signer.
#[derive(Clone)]
pub struct OpenfortSigner {
    secret_key: String,
    account_id: String,
    wallet_secret: String,
    /// Resolved by [`OpenfortSigner::init`] before any signing call.
    public_key: Option<Pubkey>,
    api_base_url: String,
    api_host: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for OpenfortSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenfortSigner")
            .field("account_id", &self.account_id)
            .field("public_key", &self.public_key)
            .field("api_base_url", &self.api_base_url)
            .finish_non_exhaustive()
    }
}

impl OpenfortSigner {
    /// Construct a signer with sensible defaults. Call [`init`](Self::init)
    /// before signing to fetch the wallet's Solana address.
    pub fn new(
        secret_key: String,
        account_id: String,
        wallet_secret: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(OpenfortSignerConfig {
            secret_key,
            account_id,
            wallet_secret,
            api_base_url: None,
            http_client_config: None,
        })
    }

    /// Construct a signer from a configuration object.
    pub fn from_config(config: OpenfortSignerConfig) -> Result<Self, SignerError> {
        if config.secret_key.is_empty() {
            return Err(SignerError::ConfigError(
                "secret_key must not be empty".to_string(),
            ));
        }
        if config.account_id.is_empty() {
            return Err(SignerError::ConfigError(
                "account_id must not be empty".to_string(),
            ));
        }
        if config.wallet_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "wallet_secret must not be empty".to_string(),
            ));
        }

        let base_url = config
            .api_base_url
            .unwrap_or_else(|| format!("https://{OPENFORT_API_HOST}"));
        let base_url = base_url.trim_end_matches('/').to_string();
        let parsed_url = reqwest::Url::parse(&base_url).map_err(|_| {
            SignerError::ConfigError(format!("Invalid Openfort base URL: {base_url}"))
        })?;
        if parsed_url.scheme() != "https" {
            return Err(SignerError::ConfigError(
                "Openfort base URL must use HTTPS".to_string(),
            ));
        }
        let api_host = extract_host(&base_url)?;
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config
            .client_builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            secret_key: config.secret_key,
            account_id: config.account_id,
            wallet_secret: config.wallet_secret,
            public_key: None,
            api_base_url: base_url,
            api_host,
            client,
        })
    }

    /// Fetch the wallet's Solana address from `GET /v2/accounts/{id}` and cache it.
    /// Must be called before [`sign_transaction`](SolanaSigner::sign_transaction)
    /// or [`sign_message`](SolanaSigner::sign_message).
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let pubkey = self.fetch_public_key().await?;
        self.public_key = Some(pubkey);
        Ok(())
    }

    fn initialized_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.public_key.ok_or_else(|| {
            SignerError::ConfigError(
                "OpenfortSigner is not initialized; call init() before signing".to_string(),
            )
        })
    }

    fn account_path(&self) -> String {
        format!("{}/{}", OPENFORT_ACCOUNTS_PATH, self.account_id)
    }

    fn sign_path(&self) -> String {
        format!("{}/{}/sign", OPENFORT_BACKEND_PATH, self.account_id)
    }

    /// `GET /v2/accounts/{accountId}` — bearer auth only, no wallet JWT.
    async fn fetch_public_key(&self) -> Result<Pubkey, SignerError> {
        let url = format!("{}{}", self.api_base_url, self.account_path());

        let response = self
            .client
            .get(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.secret_key),
            )
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("Openfort HTTP request failed: {e}")))?;

        let info: types::AccountInfo =
            parse_json_response(response, "Openfort fetch_public_key").await?;

        Pubkey::from_str(&info.address).map_err(|_| {
            SignerError::InvalidPublicKey(format!(
                "Openfort returned non-Solana address for {}: ensure the account is on an SVM chain",
                self.account_id
            ))
        })
    }

    fn build_sign_headers(
        &self,
        method: &str,
        path: &str,
        request_body: &Value,
    ) -> Result<reqwest::header::HeaderMap, SignerError> {
        let wallet_token = create_wallet_jwt(
            &self.wallet_secret,
            &self.api_host,
            method,
            path,
            request_body,
        )?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.secret_key)
                .parse()
                .map_err(|_| SignerError::ConfigError("Invalid secret_key".to_string()))?,
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .expect("valid content-type header"),
        );
        headers.insert(
            "x-wallet-auth"
                .parse::<reqwest::header::HeaderName>()
                .expect("valid header name"),
            wallet_token
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid wallet token".to_string()))?,
        );

        Ok(headers)
    }

    /// Send `POST /v2/accounts/backend/{id}/sign` with hex-encoded message bytes.
    async fn call_sign(&self, message: &[u8]) -> Result<SignResponse, SignerError> {
        let path = self.sign_path();
        let url = format!("{}{}", self.api_base_url, path);
        let data_hex = format!("0x{}", hex::encode(message));

        // Body shape exactly matches what the JWT's reqHash will be computed over.
        let body = serde_json::json!({ "data": data_hex });
        let headers = self.build_sign_headers("POST", &path, &body)?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("Openfort HTTP request failed: {e}")))?;

        parse_json_response(response, "Openfort sign").await
    }

    /// Sign arbitrary bytes via the Openfort API and verify the returned ed25519 signature.
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let response = self.call_sign(message).await?;

        let signature = signature_from_hex(&response.signature)?;
        verify_or_reject(&signature, &public_key, message)?;

        Ok(signature)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let signature = self.sign_bytes(&transaction.message.serialize()).await?;
        TransactionUtil::add_signature_to_transaction(transaction, &public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for OpenfortSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key.expect("OpenfortSigner not initialized")
    }

    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        let Some(public_key) = self.public_key else {
            return false;
        };
        match self.fetch_public_key().await {
            Ok(pubkey) => pubkey == public_key,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests;
