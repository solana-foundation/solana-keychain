//! AWS KMS signer integration using EdDSA (Ed25519) signing

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignedTransaction;
use crate::{error::SignerError, traits::SolanaSigner, transaction_util::TransactionUtil};
use aws_config::Region;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client as KmsClient,
};
use std::str::FromStr;

/// AWS KMS-based signer using EdDSA (Ed25519) signing
///
/// # Example
///
/// ```rust,ignore
/// use solana_keychain::KmsSigner;
///
/// let signer = KmsSigner::new(
///     "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string(),
///     "YourSolanaPublicKeyBase58".to_string(),
///     Some("us-east-1".to_string()),
/// ).await?;
/// ```
#[derive(Clone)]
pub struct KmsSigner {
    client: KmsClient,
    key_id: String,
    public_key: Pubkey,
    region: Option<String>,
}

impl std::fmt::Debug for KmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsSigner")
            .field("key_id", &self.key_id)
            .field("public_key", &self.public_key)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl KmsSigner {
    /// Create a new KmsSigner
    ///
    /// # Arguments
    ///
    /// * `key_id` - AWS KMS key ID or ARN (must be an ECC_NIST_EDWARDS25519 key)
    /// * `public_key` - Solana public key (base58-encoded)
    /// * `region` - Optional AWS region (defaults to default region from AWS config)
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid.
    pub async fn new(
        key_id: String,
        public_key: String,
        region: Option<String>,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        // Build AWS config
        let mut config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Some(region_str) = &region {
            config_builder = config_builder.region(Region::new(region_str.clone()));
        }

        let config = config_builder.load().await;
        let client = KmsClient::new(&config);

        Ok(Self {
            client,
            key_id,
            public_key: pubkey,
            region,
        })
    }

    /// Create a new KmsSigner with an existing KMS client
    ///
    /// This is useful for testing or when you want to configure the client yourself.
    ///
    /// # Arguments
    ///
    /// * `client` - Pre-configured AWS KMS client
    /// * `key_id` - AWS KMS key ID or ARN (must be an ECC_NIST_EDWARDS25519 key)
    /// * `public_key` - Solana public key (base58-encoded)
    pub fn with_client(
        client: KmsClient,
        key_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            client,
            key_id,
            public_key: pubkey,
            region: None,
        })
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Sign message bytes using AWS KMS EdDSA signing
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // AWS KMS Sign operation for EdDSA
        // Use ED25519_SHA_512 algorithm with RAW message type as required by AWS KMS
        // Note: The SDK may not have a typed enum variant yet since Ed25519 support
        // was added in November 2025. Using from() creates an "Unknown" variant
        // that still works with the API.
        let signing_algorithm = SigningAlgorithmSpec::from("ED25519_SHA_512");

        let response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(signing_algorithm)
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("AWS KMS Sign operation failed: {e:?}");

                SignerError::RemoteApiError(format!("AWS KMS Sign operation failed: {e}"))
            })?;

        // Extract signature from response
        let signature_blob = response.signature().ok_or_else(|| {
            SignerError::SigningFailed("No signature in AWS KMS response".to_string())
        })?;

        let signature_bytes = signature_blob.as_ref();

        // Ed25519 signatures are 64 bytes
        if signature_bytes.len() != 64 {
            return Err(SignerError::SigningFailed(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        // Convert to Signature type
        let sig_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed("Failed to convert signature bytes".to_string())
        })?;

        Ok(Signature::from(sig_bytes))
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

    /// Check if AWS KMS is available and the key is accessible
    async fn check_availability(&self) -> bool {
        // Try to describe the key as a health check
        let result = self.client.describe_key().key_id(&self.key_id).send().await;

        match result {
            Ok(response) => {
                // Verify the key spec is ECC_NIST_EDWARDS25519
                if let Some(key_metadata) = response.key_metadata() {
                    if let Some(key_spec) = key_metadata.key_spec() {
                        // Check if key spec matches ECC_NIST_EDWARDS25519
                        // The SDK may represent this as a typed enum or as Unknown("ECC_NIST_EDWARDS25519")
                        let key_spec_str = key_spec.as_str();
                        return key_spec_str == "ECC_NIST_EDWARDS25519";
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for KmsSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn sign_partial_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{Keypair, Signer};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_keypair() -> Keypair {
        Keypair::new()
    }

    const TEST_KEY_ID: &str =
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
    const TEST_REGION: &str = "us-east-1";

    #[tokio::test]
    async fn test_kms_new_invalid_pubkey() {
        // Test that invalid pubkey is caught before AWS config is loaded
        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            "not-a-valid-pubkey".to_string(),
            Some(TEST_REGION.to_string()),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_kms_new_empty_pubkey() {
        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            "".to_string(),
            Some(TEST_REGION.to_string()),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_kms_new_valid_pubkey() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            pubkey_str,
            Some(TEST_REGION.to_string()),
        )
        .await;

        // This will succeed because we only validate the pubkey format
        // AWS config loading happens but doesn't fail without credentials
        if let Ok(signer) = result {
            assert_eq!(signer.public_key, keypair.pubkey());
            assert_eq!(signer.key_id, TEST_KEY_ID);
            assert_eq!(signer.region, Some(TEST_REGION.to_string()));
        }
    }

    #[tokio::test]
    async fn test_kms_new_without_region() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(TEST_KEY_ID.to_string(), pubkey_str, None).await;

        if let Ok(signer) = result {
            assert_eq!(signer.public_key, keypair.pubkey());
            assert_eq!(signer.key_id, TEST_KEY_ID);
            assert_eq!(signer.region, None);
        }
    }

    #[tokio::test]
    async fn test_kms_pubkey() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            pubkey_str.clone(),
            Some(TEST_REGION.to_string()),
        )
        .await;

        if let Ok(signer) = result {
            assert_eq!(signer.pubkey(), keypair.pubkey());
            assert_eq!(signer.pubkey().to_string(), pubkey_str);
        }
    }

    #[tokio::test]
    async fn test_kms_key_id_accessor() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            pubkey_str,
            Some(TEST_REGION.to_string()),
        )
        .await;

        if let Ok(signer) = result {
            assert_eq!(signer.key_id(), TEST_KEY_ID);
        }
    }

    #[tokio::test]
    async fn test_kms_debug_impl() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            pubkey_str,
            Some(TEST_REGION.to_string()),
        )
        .await;

        if let Ok(signer) = result {
            let debug_str = format!("{:?}", signer);

            // Verify debug output contains expected fields
            assert!(debug_str.contains("KmsSigner"));
            assert!(debug_str.contains("key_id"));
            assert!(debug_str.contains("public_key"));
            assert!(debug_str.contains("region"));
            // Verify it doesn't leak sensitive info (no client details)
            assert!(!debug_str.contains("client"));
        }
    }

    #[tokio::test]
    async fn test_kms_key_id_variations() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let key_ids = vec![
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "12345678-1234-1234-1234-123456789012",
            "alias/my-key",
        ];

        for key_id in key_ids {
            let result = KmsSigner::new(
                key_id.to_string(),
                pubkey_str.clone(),
                Some(TEST_REGION.to_string()),
            )
            .await;

            if let Ok(signer) = result {
                assert_eq!(signer.key_id, key_id);
            }
        }
    }

    #[test]
    fn test_signing_algorithm_spec_from_str() {
        // Test that SigningAlgorithmSpec can be created from string
        let algo = SigningAlgorithmSpec::from("ED25519_SHA_512");
        let algo_str = algo.as_str();
        assert_eq!(algo_str, "ED25519_SHA_512");
    }

    #[test]
    fn test_message_type_raw() {
        // Test that MessageType::Raw is available
        let msg_type = MessageType::Raw;
        let msg_type_str = msg_type.as_str();
        assert_eq!(msg_type_str, "RAW");
    }

    #[tokio::test]
    async fn test_kms_clone() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let result = KmsSigner::new(
            TEST_KEY_ID.to_string(),
            pubkey_str,
            Some(TEST_REGION.to_string()),
        )
        .await;

        if let Ok(signer) = result {
            let cloned = signer.clone();

            assert_eq!(signer.pubkey(), cloned.pubkey());
            assert_eq!(signer.key_id, cloned.key_id);
            assert_eq!(signer.region, cloned.region);
        }
    }

    #[tokio::test]
    async fn test_kms_different_regions() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        let regions = vec!["us-east-1", "us-west-2", "eu-west-1"];

        for region in regions {
            let result = KmsSigner::new(
                TEST_KEY_ID.to_string(),
                pubkey_str.clone(),
                Some(region.to_string()),
            )
            .await;

            if let Ok(signer) = result {
                assert_eq!(signer.region, Some(region.to_string()));
            }
        }
    }

    #[test]
    fn test_signature_length_validation_logic() {
        // Valid Ed25519 signature is 64 bytes
        let valid_sig: [u8; 64] = [0u8; 64];
        assert_eq!(valid_sig.len(), 64);

        // Invalid lengths
        let invalid_sigs = vec![
            vec![0u8; 63], // Too short
            vec![0u8; 65], // Too long
            vec![0u8; 0],  // Empty
            vec![0u8; 32], // Half length
        ];

        for invalid_sig in invalid_sigs {
            assert_ne!(
                invalid_sig.len(),
                64,
                "Signature length should not be 64 bytes"
            );
        }
    }

    // Wiremock tests for actual signing operations

    /// Helper to create a KMS client configured for testing with wiremock
    fn create_test_client(endpoint_url: &str) -> KmsClient {
        use aws_config::Region;
        use aws_sdk_kms::config::{BehaviorVersion, Credentials};

        let credentials = Credentials::new("test", "test", None, None, "test");
        let config = aws_sdk_kms::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint_url)
            .credentials_provider(credentials)
            .build();
        KmsClient::from_conf(config)
    }

    #[tokio::test]
    async fn test_kms_sign_message_success() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Create the expected 64-byte Ed25519 signature
        let message = b"test message";
        let signature = keypair.sign_message(message);

        // Mock AWS KMS Sign API response
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "KeyId": TEST_KEY_ID,
                "Signature": STANDARD.encode(signature.as_ref()),
                "SigningAlgorithm": "ED25519_SHA_512"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        let result = signer.sign_message(message).await;
        assert!(result.is_ok(), "Sign message failed");
        assert_eq!(result.unwrap().as_ref().len(), 64);
    }

    #[tokio::test]
    async fn test_kms_sign_message_invalid_signature_length() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Return invalid signature (not 64 bytes)
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "KeyId": TEST_KEY_ID,
                "Signature": STANDARD.encode(vec![0u8; 32]),
                "SigningAlgorithm": "ED25519_SHA_512"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_kms_sign_api_error() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock AWS KMS error response
        Mock::given(any())
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "InvalidKeyUsageException",
                "message": "Key is not valid for signing"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_kms_sign_unauthorized() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock 403 Forbidden response (AWS uses 403 for auth errors)
        Mock::given(any())
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "__type": "AccessDeniedException",
                "message": "User is not authorized to perform kms:Sign"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_kms_is_available_success() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock DescribeKey response for availability check
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "KeyMetadata": {
                    "KeyId": TEST_KEY_ID,
                    "KeySpec": "ECC_NIST_EDWARDS25519",
                    "KeyUsage": "SIGN_VERIFY",
                    "Enabled": true
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_kms_is_available_wrong_key_spec() {
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock DescribeKey with wrong key spec (not Ed25519)
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "KeyMetadata": {
                    "KeyId": TEST_KEY_ID,
                    "KeySpec": "RSA_2048",
                    "KeyUsage": "SIGN_VERIFY",
                    "Enabled": true
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_kms_sign_transaction_success() {
        use crate::test_util::create_test_transaction;
        use wiremock::matchers::any;

        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        let mut tx = create_test_transaction(&keypair.pubkey());
        let signature = keypair.sign_message(&tx.message_data());

        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "KeyId": TEST_KEY_ID,
                "Signature": STANDARD.encode(signature.as_ref()),
                "SigningAlgorithm": "ED25519_SHA_512"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server.uri());
        let signer = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            keypair.pubkey().to_string(),
        )
        .expect("Failed to create KmsSigner");

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());

        let (base64_tx, sig) = result.unwrap();
        assert!(!base64_tx.is_empty());
        assert_eq!(sig.as_ref().len(), 64);
    }

    #[tokio::test]
    async fn test_kms_with_client_invalid_pubkey() {
        let mock_server = MockServer::start().await;
        let client = create_test_client(&mock_server.uri());

        let result = KmsSigner::with_client(
            client,
            TEST_KEY_ID.to_string(),
            "not-a-valid-pubkey".to_string(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }
}
