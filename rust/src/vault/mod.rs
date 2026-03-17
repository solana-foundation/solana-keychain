//! HashiCorp Vault signer integration

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::{
    error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner,
    transaction_util::TransactionUtil,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

/// Vault-based signer using HashiCorp Vault transit engine
#[derive(Clone)]
pub struct VaultSigner {
    client: Arc<Client>,
    vault_addr: String,
    token: String,
    key_name: String,
    pubkey: Pubkey,
}

/// Configuration for creating a VaultSigner.
#[derive(Clone)]
pub struct VaultSignerConfig {
    pub vault_addr: String,
    pub token: String,
    pub key_name: String,
    pub pubkey: String,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for VaultSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl VaultSigner {
    fn strip_vault_signature_prefix(signature: &str) -> &str {
        let Some(rest) = signature.strip_prefix("vault:v") else {
            return signature;
        };

        let Some((version, encoded_signature)) = rest.split_once(':') else {
            return signature;
        };

        if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()) {
            return signature;
        }

        encoded_signature
    }

    /// Creates a new Vault signer
    ///
    /// # Arguments
    ///
    /// * `vault_addr` - Vault server address (e.g., "https://vault.example.com")
    /// * `token` - Vault authentication token
    /// * `key_name` - Vault key name in transit engine
    /// * `pubkey` - Base58-encoded public key
    pub fn new(
        vault_addr: String,
        token: String,
        key_name: String,
        pubkey: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(VaultSignerConfig {
            vault_addr,
            token,
            key_name,
            pubkey,
            http_client_config: None,
        })
    }

    /// Creates a new Vault signer from a configuration object.
    pub fn from_config(config: VaultSignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let builder = Client::builder();
        let builder = builder
            .timeout(http_client_config.resolved_request_timeout())
            .connect_timeout(http_client_config.resolved_connect_timeout())
            .https_only(true);
        let client = builder
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        let pubkey = Pubkey::try_from(
            bs58::decode(&config.pubkey)
                .into_vec()
                .map_err(|e| {
                    SignerError::InvalidPublicKey(format!(
                        "Failed to decode base58 public key: {e}"
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key bytes: {e}")))?;

        Ok(Self {
            client: Arc::new(client),
            vault_addr: config.vault_addr,
            token: config.token,
            key_name: config.key_name,
            pubkey,
        })
    }

    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        let url = format!("{}/v1/transit/sign/{}", self.vault_addr, self.key_name);

        let payload = json!({
            "input": STANDARD.encode(serialized)
        });

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SignerError::RemoteApiError(format!("Failed to send request to Vault: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();

            let _error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Vault API error - status: {status}, response: {_error_text}");

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Vault API error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "Vault API error {}",
                status
            )));
        }

        let result: serde_json::Value = response.json().await.map_err(|_| {
            SignerError::SerializationError("Failed to parse Vault response".to_string())
        })?;

        let signature_b64 = result["data"]["signature"].as_str().ok_or_else(|| {
            SignerError::RemoteApiError("No signature in Vault response".to_string())
        })?;

        // Remove a versioned Vault transit prefix (e.g., "vault:v1:", "vault:v2:", ...).
        let signature_b64 = Self::strip_vault_signature_prefix(signature_b64);

        let sig_bytes = STANDARD.decode(signature_b64).map_err(|_| {
            SignerError::SerializationError("Failed to decode signature".to_string())
        })?;

        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| SignerError::SigningFailed("Invalid signature format".to_string()))?;

        if !sig.verify(&self.pubkey.to_bytes(), serialized) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message_data()).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.pubkey, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for VaultSigner {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
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
        // Check if we can read and validate key metadata as a health check.
        let url = format!("{}/v1/transit/keys/{}", self.vault_addr, self.key_name);

        let response = match self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => return false,
        };

        if !response.status().is_success() {
            return false;
        }

        let body: serde_json::Value = match response.json().await {
            Ok(value) => value,
            Err(_) => return false,
        };

        let supports_signing = body["data"]["supports_signing"].as_bool() == Some(true);
        let key_type_is_ed25519 = body["data"]["type"].as_str() == Some("ed25519");

        supports_signing && key_type_is_ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{Keypair, Signer};
    use crate::test_util::create_test_transaction;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_VAULT_ADDR: &str = "http://127.0.0.1:8200";
    const TEST_VAULT_TOKEN: &str = "test-token";
    const TEST_KEY_NAME: &str = "test-key";
    const TEST_PUBKEY: &str = "2vfDxWYbhRt7GXiRYKf1Dr5Z8y7zVQCSERbDTKyBaAqQ";

    fn create_test_http_client() -> Arc<Client> {
        Arc::new(Client::new())
    }

    fn create_test_signer() -> VaultSigner {
        let mut signer = VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            TEST_PUBKEY.to_string(),
        )
        .expect("Failed to create test signer");
        signer.client = create_test_http_client();
        signer
    }

    fn create_test_signer_with_pubkey(vault_addr: &str, pubkey: String) -> VaultSigner {
        let mut signer = VaultSigner::new(
            vault_addr.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            pubkey,
        )
        .expect("Failed to create test signer");
        signer.client = create_test_http_client();
        signer
    }

    #[test]
    fn test_create_vault_signer() {
        let signer = VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            TEST_PUBKEY.to_string(),
        );
        assert!(signer.is_ok());
    }

    #[test]
    fn test_invalid_pubkey() {
        let signer = VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            "invalid-pubkey".to_string(),
        );
        assert!(signer.is_err());
    }

    #[test]
    fn test_pubkey() {
        let signer = create_test_signer();
        let pubkey = signer.pubkey();
        assert_eq!(pubkey.to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_debug_impl() {
        let signer = create_test_signer();
        let debug_str = format!("{:?}", signer);
        assert!(debug_str.contains("VaultSigner"));
        assert!(debug_str.contains("pubkey"));
    }

    #[test]
    fn test_strip_vault_signature_prefix_v1() {
        assert_eq!(
            VaultSigner::strip_vault_signature_prefix("vault:v1:abc123"),
            "abc123"
        );
    }

    #[test]
    fn test_strip_vault_signature_prefix_higher_version() {
        assert_eq!(
            VaultSigner::strip_vault_signature_prefix("vault:v27:abc123"),
            "abc123"
        );
    }

    #[test]
    fn test_strip_vault_signature_prefix_no_prefix() {
        assert_eq!(
            VaultSigner::strip_vault_signature_prefix("abc123"),
            "abc123"
        );
    }

    #[test]
    fn test_strip_vault_signature_prefix_invalid_version_segment() {
        assert_eq!(
            VaultSigner::strip_vault_signature_prefix("vault:vx:abc123"),
            "vault:vx:abc123"
        );
        assert_eq!(
            VaultSigner::strip_vault_signature_prefix("vault:v:abc123"),
            "vault:v:abc123"
        );
    }

    #[tokio::test]
    async fn test_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let message = b"vault-message";
        let signature = keypair.sign_message(message);
        let signature_b64 = STANDARD.encode(signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/v1/transit/sign/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .and(body_json(serde_json::json!({
                "input": STANDARD.encode(message),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "signature": format!("vault:v1:{signature_b64}")
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer =
            create_test_signer_with_pubkey(&mock_server.uri(), keypair.pubkey().to_string());
        let result = signer.sign_message(message).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_sign_message_signature_verification_failure() {
        let mock_server = MockServer::start().await;
        let signing_keypair = Keypair::new();
        let different_keypair = Keypair::new();
        let message = b"vault-message";
        let signature = signing_keypair.sign_message(message);
        let signature_b64 = STANDARD.encode(signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/v1/transit/sign/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .and(body_json(serde_json::json!({
                "input": STANDARD.encode(message),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "signature": format!("vault:v1:{signature_b64}")
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = create_test_signer_with_pubkey(
            &mock_server.uri(),
            different_keypair.pubkey().to_string(),
        );
        let result = signer.sign_message(message).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_message_api_error() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

        Mock::given(method("POST"))
            .and(path("/v1/transit/sign/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "errors": ["unauthorized"]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"hello").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer =
            create_test_signer_with_pubkey(&mock_server.uri(), keypair.pubkey().to_string());
        let mut tx = create_test_transaction(&keypair.pubkey());
        let signature = keypair.sign_message(&tx.message_data());
        let signature_b64 = STANDARD.encode(signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/v1/transit/sign/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "signature": format!("vault:v2:{signature_b64}")
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());
        let (serialized_tx, returned_sig) = result.unwrap().into_signed_transaction();

        assert_eq!(returned_sig, signature);
        assert!(!serialized_tx.is_empty());
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0], signature);
    }

    #[tokio::test]
    async fn test_is_available_success() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "name": "test-key",
                    "supports_signing": true,
                    "type": "ed25519"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_false_for_unsupported_key_type() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "name": "test-key",
                    "supports_signing": true,
                    "type": "rsa-2048"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_false_when_key_does_not_support_signing() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "name": "test-key",
                    "supports_signing": false,
                    "type": "ed25519"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_is_available_failure() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer_with_pubkey(&mock_server.uri(), TEST_PUBKEY.to_string());

        Mock::given(method("GET"))
            .and(path("/v1/transit/keys/test-key"))
            .and(header("X-Vault-Token", TEST_VAULT_TOKEN))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "errors": ["forbidden"]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }
}
