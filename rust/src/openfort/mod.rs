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

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::signature_util::EXPECTED_SIGNATURE_LENGTH;
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
        let client = reqwest::Client::builder()
            .timeout(http_client_config.resolved_request_timeout())
            .connect_timeout(http_client_config.resolved_connect_timeout())
            .https_only(true)
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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "Openfort fetch_public_key error - status: {status}, response: {_error_text}"
            );
            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Openfort fetch_public_key error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "Openfort API error {status}"
            )));
        }

        let info: types::AccountInfo = response.json().await.map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to parse Openfort account response: {_e}");
            SignerError::SerializationError("Failed to parse Openfort account response".to_string())
        })?;

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

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Openfort sign error - status: {status}, response: {_error_text}");
            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Openfort sign error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "Openfort API error {status}"
            )));
        }

        response.json::<SignResponse>().await.map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to parse Openfort sign response: {_e}");
            SignerError::SerializationError("Failed to parse Openfort sign response".to_string())
        })
    }

    /// Sign arbitrary bytes via the Openfort API and verify the returned ed25519 signature.
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let response = self.call_sign(message).await?;

        // Signature is hex-encoded with a leading `0x`.
        let sig_hex = response.signature.trim_start_matches("0x");
        let sig_bytes = hex::decode(sig_hex).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to hex-decode Openfort signature: {_e}");
            SignerError::SerializationError("Failed to hex-decode Openfort signature".to_string())
        })?;

        let sig_array: [u8; EXPECTED_SIGNATURE_LENGTH] = sig_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed(format!(
                "Invalid signature length from Openfort (expected {EXPECTED_SIGNATURE_LENGTH} bytes)"
            ))
        })?;

        let signature = Signature::from(sig_array);

        if !signature.verify(&public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(signature)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let signature = self.sign_bytes(&transaction.message_data()).await?;
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
        tx: &mut Transaction,
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
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
    use crate::test_util::create_test_transaction;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use wiremock::{
        matchers::{header_exists, method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";
    const TEST_ACCOUNT_ID: &str = "acc_e0b84653-1741-4a3d-9e91-2b0fd2942f60";

    /// Minimal valid P-256 PKCS#8 DER, base64-encoded.
    /// Scalar is `[0x01; 32]`, which is in the valid range `[1, n-1]`.
    fn test_wallet_secret_b64() -> String {
        #[rustfmt::skip]
        const P256_PKCS8_DER: &[u8] = &[
            0x30, 0x41,
            0x02, 0x01, 0x00,
            0x30, 0x13,
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x04, 0x27,
            0x30, 0x25,
            0x02, 0x01, 0x01,
            0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        STANDARD.encode(P256_PKCS8_DER)
    }

    /// Same key wrapped in PEM headers — used to exercise the PEM-input path.
    fn test_wallet_secret_pem() -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            test_wallet_secret_b64()
        )
    }

    /// Default fixture used across most tests — bare base64 form, the same
    /// shape the Openfort dashboard and env vars deliver.
    fn test_wallet_secret() -> String {
        test_wallet_secret_b64()
    }

    /// Build a signer pointing at the mock server, with `public_key` pre-set
    /// so individual tests can skip exercising `init()`.
    fn create_test_signer(base_url: &str) -> OpenfortSigner {
        let api_host = extract_host(base_url).expect("failed to parse test base URL");
        OpenfortSigner {
            secret_key: "sk_test_secret".to_string(),
            account_id: TEST_ACCOUNT_ID.to_string(),
            wallet_secret: test_wallet_secret(),
            public_key: Some(Pubkey::from_str(TEST_PUBKEY).unwrap()),
            api_base_url: base_url.to_string(),
            api_host,
            client: reqwest::Client::new(),
        }
    }

    #[test]
    fn test_new_valid() {
        let signer = OpenfortSigner::new(
            "sk_test_secret".to_string(),
            TEST_ACCOUNT_ID.to_string(),
            test_wallet_secret(),
        );
        assert!(signer.is_ok());
        // Public key stays None until init() runs.
        assert!(signer.unwrap().public_key.is_none());
    }

    #[test]
    fn test_new_rejects_empty_fields() {
        let cases = [
            ("", TEST_ACCOUNT_ID, test_wallet_secret()),
            ("sk_test_secret", "", test_wallet_secret()),
            ("sk_test_secret", TEST_ACCOUNT_ID, String::new()),
        ];

        for (sk, account, secret) in cases {
            let result = OpenfortSigner::new(sk.to_string(), account.to_string(), secret);
            assert!(
                result.is_err(),
                "expected ConfigError for inputs with an empty field"
            );
            assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
        }
    }

    #[test]
    fn test_debug_does_not_leak_secrets() {
        let signer = create_test_signer("http://localhost");
        let debug_str = format!("{signer:?}");
        assert!(!debug_str.contains("sk_test_secret"));
        assert!(!debug_str.contains(&test_wallet_secret()));
        assert!(debug_str.contains("OpenfortSigner"));
    }

    /// Build an uninitialized signer pointing at the wiremock server with a
    /// plain HTTP client (the production builder forces https_only).
    fn create_uninitialized_test_signer(base_url: &str) -> OpenfortSigner {
        let api_host = extract_host(base_url).expect("failed to parse test base URL");
        OpenfortSigner {
            secret_key: "sk_test_secret".to_string(),
            account_id: TEST_ACCOUNT_ID.to_string(),
            wallet_secret: test_wallet_secret(),
            public_key: None,
            api_base_url: base_url.to_string(),
            api_host,
            client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn test_init_fetches_address() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": TEST_PUBKEY,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = create_uninitialized_test_signer(&mock_server.uri());
        signer.init().await.unwrap();
        assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
    }

    #[tokio::test]
    async fn test_init_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = create_uninitialized_test_signer(&mock_server.uri());
        let err = signer.init().await.unwrap_err();
        assert!(matches!(err, SignerError::RemoteApiError(_)));
    }

    #[tokio::test]
    async fn test_init_rejects_non_solana_address() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = create_uninitialized_test_signer(&mock_server.uri());
        let err = signer.init().await.unwrap_err();
        assert!(matches!(err, SignerError::InvalidPublicKey(_)));
    }

    #[tokio::test]
    async fn test_is_available_uninitialized_returns_false() {
        // No mock server needed — uninitialized signers must short-circuit
        // without issuing a request.
        let signer = create_uninitialized_test_signer("http://localhost");
        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_returns_true_when_address_matches() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": TEST_PUBKEY,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer(&mock_server.uri());
        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_returns_false_when_address_changed() {
        let mock_server = MockServer::start().await;
        let other_pubkey = keypair_pubkey(&Keypair::new()).to_string();

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": other_pubkey,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer(&mock_server.uri());
        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_returns_false_on_remote_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(format!(r"^/v2/accounts/{TEST_ACCOUNT_ID}$")))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer(&mock_server.uri());
        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_sign_message_requires_init() {
        let signer = OpenfortSigner::new(
            "sk_test_secret".to_string(),
            TEST_ACCOUNT_ID.to_string(),
            test_wallet_secret(),
        )
        .unwrap();

        let err = signer.sign_message(b"test").await.unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_wallet_secret() {
        let mut signer = create_test_signer("http://localhost");
        signer.wallet_secret = "not-a-pem-key".to_string();

        let result = signer.sign_message(b"test").await;
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPrivateKey(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);

        let test_message = b"test message";
        let signature = keypair_sign_message(&keypair, test_message);
        let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = Some(pubkey);

        Mock::given(method("POST"))
            .and(path_regex(format!(
                r"^/v2/accounts/backend/{TEST_ACCOUNT_ID}/sign$"
            )))
            .and(header_exists("authorization"))
            .and(header_exists("x-wallet-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "signature",
                "account": TEST_ACCOUNT_ID,
                "signature": sig_hex,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(test_message).await;
        assert!(result.is_ok(), "sign_message failed: {:?}", result.err());
        assert_eq!(result.unwrap().as_ref(), signature.as_ref());
    }

    #[tokio::test]
    async fn test_sign_message_signature_verification_failure() {
        let mock_server = MockServer::start().await;
        let signing_keypair = Keypair::new();
        let other_keypair = Keypair::new();
        let test_message = b"test message";
        let signature = keypair_sign_message(&signing_keypair, test_message);
        let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = Some(keypair_pubkey(&other_keypair));

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "signature",
                "account": TEST_ACCOUNT_ID,
                "signature": sig_hex,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(test_message).await;
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_signature_length() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "signature",
                "account": TEST_ACCOUNT_ID,
                "signature": "0x1234",
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_hex_signature() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "signature",
                "account": TEST_ACCOUNT_ID,
                "signature": "0xZZZZ",
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(matches!(
            result.unwrap_err(),
            SignerError::SerializationError(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign$"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);

        let mut tx = create_test_transaction(&pubkey);
        let signature = keypair_sign_message(&keypair, &tx.message_data());
        let sig_hex = format!("0x{}", hex::encode(signature.as_ref()));

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = Some(pubkey);

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "signature",
                "account": TEST_ACCOUNT_ID,
                "signature": sig_hex,
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut tx).await;
        assert!(
            result.is_ok(),
            "sign_transaction failed: {:?}",
            result.err()
        );

        let (returned_base64, returned_sig) = result.unwrap().into_signed_transaction();
        assert!(!returned_base64.is_empty());
        assert_eq!(returned_sig.as_ref(), signature.as_ref());
    }

    #[tokio::test]
    async fn test_clone() {
        let signer = create_test_signer("http://localhost");
        let clone = signer.clone();
        assert_eq!(signer.pubkey(), clone.pubkey());
    }

    #[test]
    fn test_jwt_uri_format() {
        let uri = jwt_uri(
            "api.openfort.io",
            "POST",
            "/v2/accounts/backend/acc_abc/sign",
        );
        assert_eq!(uri, "POST api.openfort.io/v2/accounts/backend/acc_abc/sign");
    }

    #[test]
    fn test_wallet_secret_to_pem_passthrough_for_pem_input() {
        let pem = test_wallet_secret_pem();
        assert_eq!(wallet_secret_to_pem(&pem), pem);
    }

    #[test]
    fn test_wallet_secret_to_pem_wraps_bare_base64() {
        let bare = test_wallet_secret_b64();
        let pem = wallet_secret_to_pem(&bare);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.contains(&bare));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        // The wrapped form must still be parseable by jsonwebtoken — exercise it.
        EncodingKey::from_ec_pem(pem.as_bytes()).expect("wrapped PEM should parse");
    }

    #[test]
    fn test_wallet_secret_to_pem_strips_whitespace_in_bare_input() {
        let bare = test_wallet_secret_b64();
        let with_whitespace = format!(" {}\n  {}  ", &bare[..20], &bare[20..]);
        let pem = wallet_secret_to_pem(&with_whitespace);
        EncodingKey::from_ec_pem(pem.as_bytes()).expect("whitespaced base64 should still parse");
    }

    #[test]
    fn test_from_config_trims_trailing_slashes() {
        let signer = OpenfortSigner::from_config(OpenfortSignerConfig {
            secret_key: "sk_test_secret".to_string(),
            account_id: TEST_ACCOUNT_ID.to_string(),
            wallet_secret: test_wallet_secret(),
            api_base_url: Some("https://api.openfort.io///".to_string()),
            http_client_config: None,
        })
        .unwrap();
        assert_eq!(signer.api_base_url, "https://api.openfort.io");
    }

    #[test]
    fn test_from_config_rejects_non_https_base_url() {
        let result = OpenfortSigner::from_config(OpenfortSignerConfig {
            secret_key: "sk_test_secret".to_string(),
            account_id: TEST_ACCOUNT_ID.to_string(),
            wallet_secret: test_wallet_secret(),
            api_base_url: Some("http://api.openfort.io".to_string()),
            http_client_config: None,
        });
        match result {
            Err(SignerError::ConfigError(msg)) => {
                assert!(msg.contains("HTTPS"), "unexpected error message: {msg}");
            }
            other => panic!("expected ConfigError for non-HTTPS base URL, got {other:?}"),
        }
    }

    #[test]
    fn test_compute_req_hash_sorted_is_key_order_invariant() {
        let body_a = serde_json::json!({ "a": 1, "b": 2 });
        let body_b = serde_json::json!({ "b": 2, "a": 1 });
        let h1 = compute_req_hash(&body_a).unwrap();
        let h2 = compute_req_hash(&body_b).unwrap();
        assert_eq!(h1, h2);
    }
}
