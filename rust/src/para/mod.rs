//! Para API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, traits::SolanaSigner};
use std::str::FromStr;
use types::{SignRawRequest, SignRawResponse, WalletResponse};

const DEFAULT_BASE_URL: &str = "https://api.getpara.com";
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Para-based signer using Para's wallet API
#[derive(Clone)]
pub struct ParaSigner {
    api_key: String,
    wallet_id: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
}

/// Configuration for creating a ParaSigner.
#[derive(Clone)]
pub struct ParaSignerConfig {
    pub api_key: String,
    pub wallet_id: String,
    pub api_base_url: Option<String>,
}

impl std::fmt::Debug for ParaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParaSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl ParaSigner {
    /// Create a new ParaSigner
    ///
    /// Validates that `api_key` starts with `sk_` and `wallet_id` is a valid UUID.
    /// Call `init()` after construction to fetch the public key from Para's API.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Para API secret key (must start with `sk_`)
    /// * `wallet_id` - Para wallet UUID
    /// * `api_base_url` - Optional custom API base URL (defaults to "https://api.getpara.com")
    pub fn new(
        api_key: String,
        wallet_id: String,
        api_base_url: Option<String>,
    ) -> Result<Self, SignerError> {
        Self::from_config(ParaSignerConfig {
            api_key,
            wallet_id,
            api_base_url,
        })
    }

    /// Create a new ParaSigner from a configuration object.
    pub fn from_config(config: ParaSignerConfig) -> Result<Self, SignerError> {
        if config.api_key.is_empty() || config.wallet_id.is_empty() {
            return Err(SignerError::ConfigError(
                "apiKey and walletId must not be empty".to_string(),
            ));
        }

        if !config.api_key.starts_with("sk_") {
            return Err(SignerError::ConfigError(
                "apiKey must be a Para secret key (starts with sk_)".to_string(),
            ));
        }

        if !Self::is_valid_uuid(&config.wallet_id) {
            return Err(SignerError::ConfigError(
                "walletId must be a valid UUID".to_string(),
            ));
        }

        if let Some(ref url) = config.api_base_url {
            if !url.starts_with("https://") {
                return Err(SignerError::ConfigError(
                    "apiBaseUrl must use HTTPS".to_string(),
                ));
            }
        }

        let builder = reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .https_only(true);
        let client = builder
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            api_key: config.api_key,
            wallet_id: config.wallet_id,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            client,
            public_key: Pubkey::default(),
        })
    }

    /// Initialize the signer by fetching the wallet and extracting the public key
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.fetch_wallet().await?;

        if !wallet.wallet_type.eq_ignore_ascii_case("SOLANA") {
            return Err(SignerError::ConfigError(format!(
                "Expected SOLANA wallet, got: {}",
                wallet.wallet_type
            )));
        }

        if !wallet.status.eq_ignore_ascii_case("ACTIVE")
            && !wallet.status.eq_ignore_ascii_case("READY")
        {
            log::warn!(
                "Para wallet status is '{}' — signing may fail",
                wallet.status
            );
        }

        let address = wallet.address.ok_or_else(|| {
            SignerError::ConfigError(
                "Wallet does not have an address (may still be creating)".to_string(),
            )
        })?;

        self.public_key = Pubkey::from_str(&address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid Solana public key from Para API".to_string())
        })?;

        Ok(())
    }

    /// Fetch wallet info from Para API
    async fn fetch_wallet(&self) -> Result<WalletResponse, SignerError> {
        let url = format!("{}/v1/wallets/{}", self.api_base_url, self.wallet_id);

        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::extract_api_error(response, "fetch_wallet").await);
        }

        Ok(response.json().await?)
    }

    /// Sign raw bytes using Para API (hex-encoded)
    async fn sign_bytes(&self, data: &[u8]) -> Result<Signature, SignerError> {
        if self.public_key == Pubkey::default() {
            return Err(SignerError::ConfigError(
                "Signer not initialized. Call init() first.".to_string(),
            ));
        }

        let url = format!(
            "{}/v1/wallets/{}/sign-raw",
            self.api_base_url, self.wallet_id
        );

        let request = SignRawRequest {
            data: hex::encode(data),
            encoding: "hex",
        };

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::extract_api_error(response, "sign_bytes").await);
        }

        let sign_response: SignRawResponse = response.json().await?;

        let hex_sig = sign_response.signature.ok_or_else(|| {
            SignerError::SigningFailed("Missing signature in response".to_string())
        })?;

        let sig = Self::decode_hex_signature(&hex_sig)?;

        if !sig.verify(&self.public_key.to_bytes(), data) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    /// Decode a hex-encoded signature string into a 64-byte Signature
    fn decode_hex_signature(hex_str: &str) -> Result<Signature, SignerError> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        if hex_str.len() != 128 {
            return Err(SignerError::SigningFailed(format!(
                "Expected 128 hex chars (64 bytes), got {} chars",
                hex_str.len()
            )));
        }

        let bytes = hex::decode(hex_str).map_err(|e| {
            SignerError::SigningFailed(format!("Failed to decode hex signature: {e}"))
        })?;

        Signature::try_from(bytes.as_slice())
            .map_err(|_| SignerError::SigningFailed("Failed to parse signature".to_string()))
    }

    /// Check wallet availability with a timeout
    async fn check_availability(&self) -> bool {
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, self.fetch_wallet()).await;

        match result {
            Ok(Ok(wallet)) => {
                wallet.wallet_type.eq_ignore_ascii_case("SOLANA")
                    && (wallet.status.eq_ignore_ascii_case("ACTIVE")
                        || wallet.status.eq_ignore_ascii_case("READY"))
            }
            _ => false,
        }
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message_data()).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.pubkey(), signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Extract error from a Para API error response.
    /// Logs details but returns only status code in the error (matches other signers).
    async fn extract_api_error(response: reqwest::Response, context: &str) -> SignerError {
        let status = response.status().as_u16();

        #[cfg(feature = "unsafe-debug")]
        {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            log::error!("Para API {context} error - status: {status}, response: {error_text}");
        }

        #[cfg(not(feature = "unsafe-debug"))]
        {
            let _ = response;
            log::error!("Para API {context} error - status: {status}");
        }

        SignerError::RemoteApiError(format!("API error {status}"))
    }

    /// Validate UUID format (matches TS UUID_REGEX)
    fn is_valid_uuid(s: &str) -> bool {
        if s.len() != 36 {
            return false;
        }
        let bytes = s.as_bytes();
        // UUID format: 8-4-4-4-12 hex chars with dashes at positions 8, 13, 18, 23
        bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-'
            && s.replace('-', "").bytes().all(|b| b.is_ascii_hexdigit())
    }
}

#[async_trait::async_trait]
impl SolanaSigner for ParaSigner {
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

    /// Check if the signer is available. Makes a network call to the Para API
    /// with a 5-second timeout. Callers should cache the result if frequent checks are needed.
    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
    use crate::test_util::create_test_transaction;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn create_test_keypair() -> Keypair {
        Keypair::new()
    }

    /// Helper to create a ParaSigner for tests, bypassing `sk_` and UUID validation.
    fn create_test_signer(api_key: &str, wallet_id: &str, base_url: Option<String>) -> ParaSigner {
        ParaSigner {
            api_key: api_key.to_string(),
            wallet_id: wallet_id.to_string(),
            api_base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            client: reqwest::Client::builder()
                .timeout(CLIENT_TIMEOUT)
                .build()
                .unwrap(),
            public_key: Pubkey::default(),
        }
    }

    // --- Validation tests ---

    #[test]
    fn test_para_new_validates_api_key_prefix() {
        let result = ParaSigner::new(
            "bad-key".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
        assert_eq!(err.to_string(), "Configuration error");
    }

    #[test]
    fn test_para_new_validates_wallet_id_uuid() {
        let result = ParaSigner::new("sk_test-key".to_string(), "not-a-uuid".to_string(), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
        assert_eq!(err.to_string(), "Configuration error");
    }

    #[test]
    fn test_para_new_validates_empty_fields() {
        let result = ParaSigner::new(
            "".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_para_new_valid() {
        let result = ParaSigner::new(
            "sk_test-key".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
            None,
        );
        assert!(result.is_ok());
        let signer = result.unwrap();
        assert_eq!(signer.api_base_url, "https://api.getpara.com");
        assert_eq!(signer.public_key, Pubkey::default());
    }

    #[test]
    fn test_para_new_custom_url_strips_trailing_slash() {
        let signer = ParaSigner::new(
            "sk_test-key".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
            Some("https://custom.api.com/".to_string()),
        )
        .unwrap();
        assert_eq!(signer.api_base_url, "https://custom.api.com");
    }

    #[test]
    fn test_uuid_validation() {
        assert!(ParaSigner::is_valid_uuid(
            "12345678-1234-1234-1234-123456789abc"
        ));
        assert!(ParaSigner::is_valid_uuid(
            "ABCDEF01-2345-6789-ABCD-EF0123456789"
        ));
        assert!(!ParaSigner::is_valid_uuid("not-a-uuid"));
        assert!(!ParaSigner::is_valid_uuid(""));
        assert!(!ParaSigner::is_valid_uuid(
            "12345678123412341234123456789abc"
        )); // no dashes
        assert!(!ParaSigner::is_valid_uuid(
            "1234567g-1234-1234-1234-123456789abc"
        )); // 'g' is not hex
    }

    // --- Sign before init ---

    #[tokio::test]
    async fn test_para_sign_before_init() {
        let signer = create_test_signer("test-api-key", "test-wallet-id", None);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    // --- Init tests ---

    #[tokio::test]
    async fn test_para_init_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "SOLANA",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_ok());
        assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
    }

    #[tokio::test]
    async fn test_para_init_case_insensitive_type() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "Solana",
                "status": "active"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        assert!(signer.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_para_init_non_solana_wallet() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": "0xabc123",
                "type": "EVM",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_para_init_no_address() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "type": "SOLANA",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_para_init_invalid_pubkey() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": "not-a-valid-pubkey",
                "type": "SOLANA",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_para_init_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Invalid API key"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("bad-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SignerError::RemoteApiError(_)));
        assert_eq!(err.to_string(), "Remote API error");
    }

    // --- Sign tests ---

    #[tokio::test]
    async fn test_para_sign_message() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        let tx = create_test_transaction(&keypair_pubkey(&keypair));
        let signature = keypair.sign_message(&tx.message_data());
        let sig_hex = hex::encode(signature);

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .and(header("X-API-Key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": sig_hex
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(&tx.message_data()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_para_sign_message_0x_prefix() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        let tx = create_test_transaction(&keypair_pubkey(&keypair));
        let signature = keypair.sign_message(&tx.message_data());
        let sig_hex = format!("0x{}", hex::encode(signature));

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": sig_hex
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(&tx.message_data()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_para_sign_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        let mut tx = create_test_transaction(&keypair_pubkey(&keypair));
        let signature = keypair.sign_message(&tx.message_data());
        let sig_hex = hex::encode(signature);

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": sig_hex
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());
        let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();
        assert_eq!(returned_sig, signature);
        assert!(!serialized_tx.is_empty());
    }

    #[tokio::test]
    async fn test_para_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Unauthorized"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("bad-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_para_sign_missing_signature() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_para_sign_invalid_hex_length() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": "aabbccdd"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    // --- is_available tests ---

    #[tokio::test]
    async fn test_para_is_available_ready() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "SOLANA",
                "status": "READY"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_is_available_active() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "SOLANA",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_is_available_creating() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "SOLANA",
                "status": "CREATING"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_is_available_non_solana() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": "0xabc123",
                "type": "EVM",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_is_available_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_sign_invalid_hex_chars() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // 128 chars but contains invalid hex characters ('z', 'q')
        let bad_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": bad_hex
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_para_init_malformed_json() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_para_sign_malformed_json() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_para_init_creating_status_with_address() {
        // init() does not check status (matches TS behavior) — only is_available() does
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "type": "SOLANA",
                "status": "CREATING"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        assert!(signer.init().await.is_ok());
        assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
    }

    #[tokio::test]
    async fn test_para_init_missing_type_field() {
        let mock_server = MockServer::start().await;

        // Missing "type" field — serde deserialization should fail early
        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": "11111111111111111111111111111111",
                "status": "ACTIVE"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        let result = signer.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_para_is_available_timeout() {
        let mock_server = MockServer::start().await;

        // Respond with a 10-second delay — exceeds the 5s timeout
        Mock::given(method("GET"))
            .and(path("/v1/wallets/test-wallet-id"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "id": "test-wallet-id",
                        "address": "11111111111111111111111111111111",
                        "type": "SOLANA",
                        "status": "ACTIVE"
                    }))
                    .set_delay(std::time::Duration::from_secs(10)),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_para_debug_hides_secrets() {
        let signer = create_test_signer("secret-api-key", "secret-wallet-id", None);

        let debug_str = format!("{:?}", signer);
        assert!(!debug_str.contains("secret-api-key"));
        assert!(!debug_str.contains("secret-wallet-id"));
        assert!(debug_str.contains("ParaSigner"));
    }

    #[tokio::test]
    async fn test_para_error_status_code_only() {
        // Display output should stay generic and never include API response text.
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "Wallet is locked"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "Remote API error");
        assert!(!err.to_string().contains("Wallet is locked"));
    }

    #[test]
    fn test_para_new_rejects_http_url() {
        let result = ParaSigner::new(
            "sk_test-key".to_string(),
            "12345678-1234-1234-1234-123456789abc".to_string(),
            Some("http://insecure.example.com".to_string()),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_para_sign_verification_failure() {
        // If API returns a bad signature that doesn't verify, we should get an error
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Return a valid-format but wrong signature (64 zero bytes)
        let bad_sig_hex = "00".repeat(64);

        Mock::given(method("POST"))
            .and(path("/v1/wallets/test-wallet-id/sign-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signature": bad_sig_hex
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer =
            create_test_signer("test-api-key", "test-wallet-id", Some(mock_server.uri()));
        signer.public_key = keypair_pubkey(&keypair);

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }
}
