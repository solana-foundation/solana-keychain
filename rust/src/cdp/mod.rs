//! CDP (Coinbase Developer Platform) signer integration

mod jwt;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::str::FromStr;

use self::jwt::{create_auth_jwt, create_wallet_jwt, extract_host};
use self::types::{SignMessageResponse, SignTransactionResponse};

use crate::signature_util::EXPECTED_SIGNATURE_LENGTH;

const CDP_API_HOST: &str = "api.cdp.coinbase.com";
const CDP_BASE_PATH: &str = "/platform/v2/solana/accounts";

// ─── CdpSigner ────────────────────────────────────────────────────────────────

/// CDP (Coinbase Developer Platform) Solana signer.
///
/// Signs Solana transactions and messages using CDP's managed key infrastructure
/// via the CDP REST API. The account address must be provided at construction time.
///
/// # Authentication
///
/// CDP uses two JWTs per signing request:
/// - `Authorization: Bearer <jwt>` — main API auth (Ed25519 or ES256)
/// - `X-Wallet-Auth: <jwt>` — wallet auth for write endpoints (ES256)
///
/// # Example
///
/// ```rust,no_run
/// use solana_keychain::{CdpSigner, SolanaSigner};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let signer = CdpSigner::new(
///         std::env::var("CDP_API_KEY_ID")?,
///         std::env::var("CDP_API_KEY_SECRET")?,
///         std::env::var("CDP_WALLET_SECRET")?,
///         std::env::var("CDP_SOLANA_ADDRESS")?,
///     )?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct CdpSigner {
    api_key_id: String,
    api_key_secret: String,
    wallet_secret: String,
    public_key: Pubkey,
    api_base_url: String,
    api_host: String,
    client: reqwest::Client,
}

/// Configuration for creating a CdpSigner.
#[derive(Clone)]
pub struct CdpSignerConfig {
    pub api_key_id: String,
    pub api_key_secret: String,
    pub wallet_secret: String,
    pub address: String,
    pub api_base_url: Option<String>,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for CdpSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdpSigner")
            .field("public_key", &self.public_key)
            .field("api_base_url", &self.api_base_url)
            .finish_non_exhaustive()
    }
}

impl CdpSigner {
    /// Create a new CdpSigner.
    ///
    /// # Arguments
    ///
    /// * `api_key_id` - CDP API key name / ID
    /// * `api_key_secret` - CDP API private key (base64 Ed25519)
    /// * `wallet_secret` - CDP wallet secret (base64 PKCS#8 DER for ES256)
    /// * `address` - Solana account address managed by CDP (base58 pubkey)
    pub fn new(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(CdpSignerConfig {
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            api_base_url: None,
            http_client_config: None,
        })
    }

    /// Create a new CdpSigner from a configuration object.
    pub fn from_config(config: CdpSignerConfig) -> Result<Self, SignerError> {
        if config.api_key_id.is_empty() {
            return Err(SignerError::ConfigError(
                "api_key_id must not be empty".to_string(),
            ));
        }
        if config.api_key_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "api_key_secret must not be empty".to_string(),
            ));
        }
        if config.wallet_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "wallet_secret must not be empty".to_string(),
            ));
        }
        if config.address.is_empty() {
            return Err(SignerError::ConfigError(
                "address must not be empty".to_string(),
            ));
        }

        let public_key = Pubkey::from_str(&config.address).map_err(|_| {
            SignerError::InvalidPublicKey(format!("Invalid Solana address: {}", config.address))
        })?;

        let base_url = config
            .api_base_url
            .unwrap_or_else(|| format!("https://{CDP_API_HOST}"));
        let api_host = extract_host(&base_url)?;
        let http_client_config = config.http_client_config.unwrap_or_default();
        let builder = reqwest::Client::builder();
        let builder = builder
            .timeout(http_client_config.resolved_request_timeout())
            .connect_timeout(http_client_config.resolved_connect_timeout())
            .https_only(true);
        let client = builder
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            api_key_id: config.api_key_id,
            api_key_secret: config.api_key_secret,
            wallet_secret: config.wallet_secret,
            public_key,
            api_base_url: base_url,
            api_host,
            client,
        })
    }

    /// Build authenticated request headers for a given method and path.
    fn build_auth_headers(
        &self,
        method: &str,
        path: &str,
        request_body: Option<&Value>,
    ) -> Result<reqwest::header::HeaderMap, SignerError> {
        let auth_token = create_auth_jwt(
            &self.api_key_id,
            &self.api_key_secret,
            &self.api_host,
            method,
            path,
        )?;
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
            format!("Bearer {auth_token}")
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid auth token".to_string()))?,
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json"
                .parse()
                .expect("valid content-type header"),
        );
        headers.insert(
            "X-Wallet-Auth"
                .parse::<reqwest::header::HeaderName>()
                .expect("valid header name"),
            wallet_token
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid wallet token".to_string()))?,
        );

        Ok(headers)
    }

    /// Build auth headers for GET requests (no wallet auth needed).
    fn build_get_headers(&self, path: &str) -> Result<reqwest::header::HeaderMap, SignerError> {
        let auth_token = create_auth_jwt(
            &self.api_key_id,
            &self.api_key_secret,
            &self.api_host,
            "GET",
            path,
        )?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {auth_token}")
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid auth token".to_string()))?,
        );

        Ok(headers)
    }

    /// Sign a Solana transaction via the CDP API.
    async fn call_sign_transaction(
        &self,
        base64_tx: &str,
    ) -> Result<SignTransactionResponse, SignerError> {
        let path = format!("{}/{}/sign/transaction", CDP_BASE_PATH, self.public_key);
        let url = format!("{}{}", self.api_base_url, path);

        let body = serde_json::json!({ "transaction": base64_tx });
        let headers = self.build_auth_headers("POST", &path, Some(&body))?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("CDP HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("CDP sign_transaction error - status: {status}, response: {_error_text}");
            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("CDP sign_transaction error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "CDP API error {status}"
            )));
        }

        response
            .json::<SignTransactionResponse>()
            .await
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to parse CDP sign_transaction response: {_e}");
                SignerError::SerializationError(
                    "Failed to parse CDP sign_transaction response".to_string(),
                )
            })
    }

    /// Sign a message via the CDP API.
    async fn call_sign_message(&self, message: &str) -> Result<SignMessageResponse, SignerError> {
        let path = format!("{}/{}/sign/message", CDP_BASE_PATH, self.public_key);
        let url = format!("{}{}", self.api_base_url, path);

        let body = serde_json::json!({ "message": message });
        let headers = self.build_auth_headers("POST", &path, Some(&body))?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("CDP HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("CDP sign_message error - status: {status}, response: {_error_text}");
            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("CDP sign_message error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "CDP API error {status}"
            )));
        }

        response.json::<SignMessageResponse>().await.map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to parse CDP sign_message response: {_e}");
            SignerError::SerializationError("Failed to parse CDP sign_message response".to_string())
        })
    }

    /// Sign message bytes using the CDP API.
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // CDP signMessage API takes a UTF-8 string
        let message_str = std::str::from_utf8(message).map_err(|_e| {
            SignerError::SerializationError(
                "CDP signMessage requires UTF-8; non-UTF-8 bytes are not supported".to_string(),
            )
        })?;
        let response = self.call_sign_message(message_str).await?;

        // CDP returns a base58-encoded signature
        let sig_bytes = bs58::decode(&response.signature).into_vec().map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to decode base58 signature: {_e}");
            SignerError::SerializationError(
                "Failed to decode base58 signature from CDP".to_string(),
            )
        })?;

        let sig_array: [u8; EXPECTED_SIGNATURE_LENGTH] = sig_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed(format!(
                "Invalid signature length from CDP (expected {EXPECTED_SIGNATURE_LENGTH} bytes)"
            ))
        })?;

        let sig = Signature::from(sig_array);

        if !sig.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    /// Sign and serialize a Solana transaction via CDP.
    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message_data();
        let signer_position =
            TransactionUtil::get_signing_keypair_position(transaction, &self.public_key)?;

        // Serialize the full transaction to bytes (Solana wire format)
        let serialized = bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;
        let base64_tx = STANDARD.encode(&serialized);

        let response = self.call_sign_transaction(&base64_tx).await?;

        // Decode and deserialize the returned signed transaction
        let signed_bytes = STANDARD
            .decode(&response.signed_transaction)
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to decode base64 signed transaction: {_e}");
                SignerError::SerializationError(
                    "Failed to decode base64 signed transaction from CDP".to_string(),
                )
            })?;

        let signed_tx: Transaction = bincode::deserialize(&signed_bytes).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to deserialize signed transaction: {_e}");
            SignerError::SerializationError(
                "Failed to deserialize signed transaction from CDP".to_string(),
            )
        })?;

        // Extract only our signature from the response and apply it to the original transaction.
        let signature = *signed_tx.signatures.get(signer_position).ok_or_else(|| {
            SignerError::SigningFailed(
                "Signature not found at expected position in CDP response".to_string(),
            )
        })?;

        if !signature.verify(&self.public_key.to_bytes(), &message_data) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if CDP API is reachable by fetching the account info.
    async fn check_availability(&self) -> bool {
        let path = format!("{}/{}", CDP_BASE_PATH, self.public_key);

        let headers = match self.build_get_headers(&path) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let url = format!("{}{}", self.api_base_url, path);
        match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

// ─── SolanaSigner Implementation ─────────────────────────────────────────────

#[async_trait::async_trait]
impl SolanaSigner for CdpSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
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
        self.check_availability().await
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::jwt;
    use super::*;
    use crate::sdk_adapter::{
        keypair_from_seed, keypair_pubkey, keypair_sign_message, Keypair, Pubkey,
    };
    use crate::test_util::{create_test_transaction, create_test_transaction_with_recipient};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use wiremock::{
        matchers::{method, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_PUBKEY: &str = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";

    /// Generate a 64-byte random Ed25519 key in the CDP base64 format (seed || pubkey).
    /// This must be a real keypair to pass JWT validation.
    fn test_ed25519_key() -> String {
        let seed = [0x42u8; 32];
        let keypair = keypair_from_seed(&seed).expect("failed to derive test keypair");
        let pubkey = keypair_pubkey(&keypair).to_bytes();

        let mut key_bytes = [0u8; 64];
        key_bytes[..32].copy_from_slice(&seed);
        key_bytes[32..].copy_from_slice(pubkey.as_ref());
        STANDARD.encode(key_bytes)
    }

    /// Return a valid wallet secret for tests: base64 of a minimal P-256 PKCS#8 DER.
    ///
    /// Structure (67 bytes):
    ///   SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID prime256v1 },
    ///     OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING [32-byte scalar] } } }
    fn test_wallet_secret() -> String {
        #[rustfmt::skip]
        const P256_PKCS8_DER: &[u8] = &[
            // outer SEQUENCE (65 bytes)
            0x30, 0x41,
            // version INTEGER 0
            0x02, 0x01, 0x00,
            // AlgorithmIdentifier SEQUENCE (19 bytes)
            0x30, 0x13,
            // OID ecPublicKey (1.2.840.10045.2.1)
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            // OID prime256v1 (1.2.840.10045.3.1.7)
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            // privateKey OCTET STRING (39 bytes)
            0x04, 0x27,
            // ECPrivateKey SEQUENCE (37 bytes)
            0x30, 0x25,
            // version INTEGER 1
            0x02, 0x01, 0x01,
            // privateKey OCTET STRING (32 bytes) — scalar in [1, n-1]
            0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        STANDARD.encode(P256_PKCS8_DER)
    }

    fn create_test_signer(base_url: &str) -> CdpSigner {
        let api_host = extract_host(base_url).expect("failed to parse test base URL");
        CdpSigner {
            api_key_id: "test-api-key".to_string(),
            api_key_secret: test_ed25519_key(),
            wallet_secret: test_wallet_secret(),
            public_key: Pubkey::from_str(TEST_PUBKEY).unwrap(),
            api_base_url: base_url.to_string(),
            api_host,
            client: reqwest::Client::new(),
        }
    }

    #[test]
    fn test_new_valid() {
        let signer = CdpSigner::new(
            "test-key".to_string(),
            test_ed25519_key(),
            test_wallet_secret(),
            TEST_PUBKEY.to_string(),
        );

        assert!(signer.is_ok());
        let signer = signer.unwrap();
        assert_eq!(signer.public_key.to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_new_empty_api_key_id() {
        let result = CdpSigner::new(
            "".to_string(),
            "private".to_string(),
            "secret".to_string(),
            TEST_PUBKEY.to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_new_empty_api_key_secret() {
        let result = CdpSigner::new(
            "key".to_string(),
            "".to_string(),
            "secret".to_string(),
            TEST_PUBKEY.to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_new_empty_wallet_secret() {
        let result = CdpSigner::new(
            "key".to_string(),
            "private".to_string(),
            "".to_string(),
            TEST_PUBKEY.to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_new_empty_address() {
        let result = CdpSigner::new(
            "key".to_string(),
            "private".to_string(),
            "secret".to_string(),
            "".to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_new_invalid_address() {
        let result = CdpSigner::new(
            "key".to_string(),
            "private".to_string(),
            "secret".to_string(),
            "not-a-valid-pubkey".to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[test]
    fn test_pubkey() {
        let signer = create_test_signer("http://localhost");
        assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_debug_does_not_leak_secrets() {
        let signer = create_test_signer("http://localhost");
        let debug_str = format!("{signer:?}");
        assert!(!debug_str.contains(&test_ed25519_key()));
        assert!(!debug_str.contains(&test_wallet_secret()));
        assert!(debug_str.contains("CdpSigner"));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_api_key_secret() {
        let mut signer = create_test_signer("http://localhost");
        signer.api_key_secret = "not-base64".to_string();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPrivateKey(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_wallet_secret() {
        let mut signer = create_test_signer("http://localhost");
        signer.wallet_secret = "not-base64".to_string();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
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

        // Create a valid 64-byte signature
        let test_message = b"test message";
        let signature = keypair_sign_message(&keypair, test_message);
        let sig_base58 = bs58::encode(signature.as_ref()).into_string();

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = pubkey;

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/message$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": sig_base58
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
        let different_keypair = Keypair::new();
        let test_message = b"test message";
        let signature = keypair_sign_message(&signing_keypair, test_message);
        let sig_base58 = bs58::encode(signature.as_ref()).into_string();

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = keypair_pubkey(&different_keypair);

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/message$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": sig_base58
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(test_message).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_message_api_error() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/message$"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_signature_length() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        // Return a base58-encoded value that decodes to != 64 bytes
        let short_sig = bs58::encode(&[0u8; 10]).into_string();

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/message$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": short_sig
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);

        let mut tx = create_test_transaction(&pubkey);
        let signature = keypair_sign_message(&keypair, &tx.message_data());

        let mut signed_tx = tx.clone();
        signed_tx.signatures = vec![signature];

        // Serialize the signed transaction to get the base64 wire format
        let serialized = bincode::serialize(&signed_tx).unwrap();
        let base64_signed_tx = STANDARD.encode(&serialized);

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = pubkey;

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/transaction$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signedTransaction": base64_signed_tx
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
        assert_eq!(
            returned_base64,
            TransactionUtil::serialize_transaction(&tx).unwrap()
        );
    }

    #[tokio::test]
    async fn test_sign_transaction_rejects_tampered_remote_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);

        let mut tx = create_test_transaction(&pubkey);
        let original_message = tx.message.clone();

        // Simulate a compromised API returning a signature over a different transaction.
        let tampered_recipient = Pubkey::new_unique();
        let mut tampered_tx = create_test_transaction_with_recipient(&pubkey, &tampered_recipient);
        let tampered_signature = keypair_sign_message(&keypair, &tampered_tx.message_data());
        tampered_tx.signatures = vec![tampered_signature];

        let serialized = bincode::serialize(&tampered_tx).unwrap();
        let base64_signed_tx = STANDARD.encode(&serialized);

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = pubkey;

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/transaction$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signedTransaction": base64_signed_tx
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
        assert_eq!(tx.message, original_message);
    }

    #[tokio::test]
    async fn test_sign_transaction_api_error() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("POST"))
            .and(path_regex(r".*/sign/transaction$"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&Pubkey::from_str(TEST_PUBKEY).unwrap());
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_is_available_success() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path_regex(r".*/accounts/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": TEST_PUBKEY
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_failure() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path_regex(r".*/accounts/.*"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_clone() {
        let signer = create_test_signer("http://localhost");
        let clone = signer.clone();
        assert_eq!(signer.pubkey(), clone.pubkey());
    }

    #[test]
    fn test_der_to_pkcs8_pem() {
        let der = vec![0x30u8, 0x2e, 0x01]; // minimal fake DER
        let pem = jwt::der_to_pkcs8_pem(&der);
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_jwt_uri_format() {
        let uri = jwt::jwt_uri(
            "api.cdp.coinbase.com",
            "POST",
            "/platform/v2/solana/accounts/abc/sign/transaction",
        );
        assert_eq!(
            uri,
            "POST api.cdp.coinbase.com/platform/v2/solana/accounts/abc/sign/transaction"
        );
    }

    #[test]
    fn test_wallet_jwt_includes_req_hash() {
        let request_body = serde_json::json!({
            "b": 2,
            "a": {
                "d": 4,
                "c": 3
            }
        });

        let expected_hash =
            jwt::compute_req_hash(Some(&request_body)).expect("failed to compute reqHash");

        let token = create_wallet_jwt(
            &test_wallet_secret(),
            "api.cdp.coinbase.com",
            "POST",
            "/platform/v2/solana/accounts/abc/sign/message",
            Some(&request_body),
        )
        .expect("failed to create wallet JWT");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("failed to decode JWT payload");
        let payload: Value =
            serde_json::from_slice(&payload_bytes).expect("failed to parse JWT payload");

        let req_hash = payload
            .get("reqHash")
            .and_then(|value| value.as_str())
            .expect("reqHash missing in wallet JWT payload");

        assert_eq!(Some(req_hash.to_string()), expected_hash);
    }
}
