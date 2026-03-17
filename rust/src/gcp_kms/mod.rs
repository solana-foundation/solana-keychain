//! Google Cloud KMS signer integration using EdDSA (Ed25519) signing

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner};
use crate::transaction_util::TransactionUtil;
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use std::str::FromStr;

/// GCP KMS-based signer using EdDSA (Ed25519) signing
///
/// # Example
///
/// ```rust,ignore
/// use solana_keychain::GcpKmsSigner;
///
/// let signer = GcpKmsSigner::new(
///     "projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1".to_string(),
///     "YourSolanaPublicKeyBase58".to_string(),
/// ).await?;
/// ```
#[derive(Clone)]
pub struct GcpKmsSigner {
    client: KeyManagementService,
    key_name: String,
    public_key: Pubkey,
}

/// Configuration for creating a GcpKmsSigner.
#[derive(Clone)]
pub struct GcpKmsSignerConfig {
    pub key_name: String,
    pub public_key: String,
}

impl std::fmt::Debug for GcpKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsSigner")
            .field("key_name", &self.key_name)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl GcpKmsSigner {
    /// Create a new GcpKmsSigner
    ///
    /// # Arguments
    ///
    /// * `key_name` - Full resource name of the crypto key version
    /// * `public_key` - Solana public key (base58-encoded)
    pub async fn new(key_name: String, public_key: String) -> Result<Self, SignerError> {
        Self::from_config(GcpKmsSignerConfig {
            key_name,
            public_key,
        })
        .await
    }

    /// Create a new GcpKmsSigner from a configuration object.
    pub async fn from_config(config: GcpKmsSignerConfig) -> Result<Self, SignerError> {
        let client = KeyManagementService::builder().build().await.map_err(|e| {
            SignerError::RemoteApiError(format!("Failed to create KMS client: {e}"))
        })?;

        Self::with_client(client, config.key_name, config.public_key)
    }

    /// Create a new GcpKmsSigner with a pre-configured client
    pub fn with_client(
        client: KeyManagementService,
        key_name: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            client,
            key_name,
            public_key: pubkey,
        })
    }

    /// Get the GCP KMS key name
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Sign message bytes using GCP KMS EdDSA signing
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // GCP KMS AsymmetricSign with EC_SIGN_ED25519 takes raw data directly
        // because it operates in PureEdDSA mode
        let response = self
            .client
            .asymmetric_sign()
            .set_name(&self.key_name)
            .set_data(message.to_vec())
            .send()
            .await
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("GCP KMS Sign operation failed: {_e:?}");

                SignerError::RemoteApiError("GCP KMS Sign operation failed".to_string())
            })?;

        // Extract signature from response
        let signature_bytes = response.signature.as_ref();

        if signature_bytes.is_empty() {
            return Err(SignerError::SigningFailed(
                "No signature in GCP KMS response".to_string(),
            ));
        }

        // Ed25519 signatures are 64 bytes
        if signature_bytes.len() != 64 {
            return Err(SignerError::SigningFailed(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        let sig_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed("Failed to convert signature bytes".to_string())
        })?;

        let sig = Signature::from(sig_bytes);

        if !sig.verify(&self.public_key.to_bytes(), message) {
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

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if GCP KMS is available and the key is accessible
    async fn check_availability(&self) -> bool {
        // Try to get the public key as a health check
        let result = self
            .client
            .get_public_key()
            .set_name(&self.key_name)
            .send()
            .await;

        match result {
            Ok(public_key) => {
                // Verify the algorithm is EC_SIGN_ED25519
                public_key.algorithm == CryptoKeyVersionAlgorithm::EcSignEd25519
            }
            Err(_e) => {
                #[cfg(feature = "unsafe-debug")]
                log::error!("GCP KMS availability check failed: {_e:?}");

                false
            }
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for GcpKmsSigner {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{Keypair, Signer};
    use crate::test_util::create_test_transaction;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use google_cloud_kms_v1::client::KeyManagementService;
    use scoped_env::ScopedEnv;
    use serial_test::serial;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_KEY_NAME: &str = "projects/test-project/locations/us-east1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1";

    fn create_test_keypair() -> Keypair {
        Keypair::new()
    }

    /// Helper to create a KMS client configured for testing with wiremock
    async fn create_test_client(endpoint: &str) -> KeyManagementService {
        KeyManagementService::builder()
            .with_endpoint(endpoint)
            .build()
            .await
            .expect("Failed to create mock client")
    }

    #[tokio::test]
    async fn test_gcp_kms_new_invalid_pubkey() {
        let client = KeyManagementService::builder().build().await.unwrap();
        let result = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            "invalid-pubkey".to_string(),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_gcp_kms_new_empty_pubkey() {
        let client = KeyManagementService::builder().build().await.unwrap();
        let result = GcpKmsSigner::with_client(client, TEST_KEY_NAME.to_string(), "".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_gcp_kms_new_valid_pubkey() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

        if let Ok(signer) = result {
            assert_eq!(signer.public_key, keypair.pubkey());
            assert_eq!(signer.key_name, TEST_KEY_NAME);
        }
    }

    #[tokio::test]
    async fn test_gcp_kms_pubkey() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str.clone()).await;

        if let Ok(signer) = result {
            assert_eq!(signer.pubkey(), keypair.pubkey());
            assert_eq!(signer.pubkey().to_string(), pubkey_str);
        }
    }

    #[tokio::test]
    async fn test_gcp_kms_key_id_accessor() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

        if let Ok(signer) = result {
            assert_eq!(signer.key_name(), TEST_KEY_NAME);
        }
    }

    #[tokio::test]
    async fn test_gcp_kms_debug_impl() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = GcpKmsSigner::new(TEST_KEY_NAME.to_string(), pubkey_str).await;

        if let Ok(signer) = result {
            let debug_str = format!("{:?}", signer);

            assert!(debug_str.contains("GcpKmsSigner"));
            assert!(debug_str.contains("key_name"));
            assert!(debug_str.contains("public_key"));
            assert!(!debug_str.contains("client"));
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_is_available_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        // Mock GetPublicKey
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "name": TEST_KEY_NAME,
                    "algorithm": "EC_SIGN_ED25519"
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        let message = b"test message";
        let signature = keypair.sign_message(message);

        // Mock AsymmetricSign
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "signature": STANDARD.encode(signature.as_ref()),
                    "verified_data_crc32c": true
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(result.is_ok(), "Sign message failed");
        assert_eq!(result.unwrap().as_ref().len(), 64);
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_sign_message_signature_verification_failure() {
        let mock_server = MockServer::start().await;
        let signing_keypair = create_test_keypair();
        let different_keypair = create_test_keypair();

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            different_keypair.pubkey().to_string(),
        );
        assert!(signer.is_ok());
        let signer = signer.unwrap();

        let message = b"test message";
        let signature = signing_keypair.sign_message(message);

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "signature": STANDARD.encode(signature.as_ref()),
                    "verified_data_crc32c": true
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        // Create a dummy transaction
        let mut tx = create_test_transaction(&keypair.pubkey());
        let signature = keypair.sign_message(&tx.message_data());

        // Mock AsymmetricSign
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "signature": STANDARD.encode(signature.as_ref()),
                    "verified_data_crc32c": true
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut tx).await;
        assert!(
            result.is_ok(),
            "Sign transaction failed: {:#?}",
            result.err()
        );

        let (base64_tx, sig) = result.unwrap().into_signed_transaction();
        assert!(!base64_tx.is_empty());
        assert_eq!(sig.as_ref().len(), 64);
        assert_eq!(sig, signature);
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_sign_message_invalid_signature_length() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        // Return invalid signature (not 64 bytes)
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "signature": STANDARD.encode(vec![0u8; 32]),
                    "verified_data_crc32c": true
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    #[serial]
    async fn test_gcp_kms_sign_api_error() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        Mock::given(any())
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!(
                {
                    "error": {
                        "code": 400,
                        "message": "Key is not valid for signing",
                        "status": "INVALID_ARGUMENT"
                    }
                }
            )))
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
    #[serial]
    async fn test_gcp_kms_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        // Mock 403 Forbidden
        Mock::given(any())
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!(
                {
                    "error": {
                        "code": 403,
                        "message": "Permission denied",
                        "status": "PERMISSION_DENIED"
                    }
                }
            )))
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
    #[serial]
    async fn test_gcp_kms_is_available_wrong_algorithm() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock Metadata server for auth token
        Mock::given(method("GET"))
            .and(path(
                "/computeMetadata/v1/instance/service-accounts/default/token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "access_token": "mock-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }
            )))
            .mount(&mock_server)
            .await;

        let metadata_host = mock_server.address().to_string();
        let _env = ScopedEnv::set("GCE_METADATA_HOST", &metadata_host);

        let client = create_test_client(&mock_server.uri()).await;
        let signer = GcpKmsSigner::with_client(
            client,
            TEST_KEY_NAME.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create signer");

        // Mock GetPublicKey with WRONG algorithm
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!(
                {
                    "name": TEST_KEY_NAME,
                    "algorithm": "RSA_SIGN_PSS_2048_SHA256"
                }
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(
            !signer.is_available().await,
            "Availability check should fail for wrong algorithm"
        );
    }
}
