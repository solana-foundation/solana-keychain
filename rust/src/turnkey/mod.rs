//! Turnkey API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
pub use crate::traits::SignedTransaction;
use crate::{error::SignerError, traits::SolanaSigner, transaction_util::TransactionUtil};
use base64::Engine;
use p256::ecdsa::signature::Signer as P256Signer;
use std::str::FromStr;
use types::{ActivityResponse, SignParameters, SignRequest, WhoAmIRequest};

/// Turnkey-based signer using Turnkey's API
#[derive(Clone)]
pub struct TurnkeySigner {
    organization_id: String,
    private_key_id: String,
    api_public_key: String,
    api_private_key: String,
    public_key: Pubkey,
    api_base_url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for TurnkeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeySigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl TurnkeySigner {
    /// Create a new TurnkeySigner
    ///
    /// # Arguments
    ///
    /// * `api_public_key` - Turnkey API public key
    /// * `api_private_key` - Turnkey API private key (hex-encoded)
    /// * `organization_id` - Turnkey organization ID
    /// * `private_key_id` - Turnkey private key ID
    /// * `public_key` - Solana public key (base58-encoded)
    pub fn new(
        api_public_key: String,
        api_private_key: String,
        organization_id: String,
        private_key_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            api_public_key,
            api_private_key,
            organization_id,
            private_key_id,
            public_key: pubkey,
            api_base_url: "https://api.turnkey.com".to_string(),
            client: reqwest::Client::new(),
        })
    }

    /// Sign message bytes using Turnkey API and return just the signature
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let hex_message = hex::encode(message);

        let request = SignRequest {
            activity_type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2".to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis().to_string(),
            organization_id: self.organization_id.clone(),
            parameters: SignParameters {
                sign_with: self.private_key_id.clone(),
                payload: hex_message,
                encoding: "PAYLOAD_ENCODING_HEXADECIMAL".to_string(),
                hash_function: "HASH_FUNCTION_NOT_APPLICABLE".to_string(),
            },
        };

        let body = serde_json::to_string(&request)?;
        let stamp = self.create_stamp(&body)?;

        let url = format!("{}/public/v1/submit/sign_raw_payload", self.api_base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Stamp", stamp)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Turnkey API error - status: {status}, response: {error_text}");

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Turnkey API error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let response_text = response.text().await?;
        let response: ActivityResponse = serde_json::from_str(&response_text)?;

        if let Some(result) = response.activity.result {
            if let Some(sign_result) = result.sign_raw_payload_result {
                // Decode r and s components
                let r_bytes = hex::decode(&sign_result.r).map_err(|e| {
                    SignerError::SerializationError(format!("Failed to decode r: {e}"))
                })?;
                let s_bytes = hex::decode(&sign_result.s).map_err(|e| {
                    SignerError::SerializationError(format!("Failed to decode s: {e}"))
                })?;

                // Ensure each component is exactly 32 bytes
                if r_bytes.len() > 32 || s_bytes.len() > 32 {
                    return Err(SignerError::SigningFailed(
                        "Invalid signature component length".to_string(),
                    ));
                }

                // Create properly padded 32-byte arrays
                let mut final_r = [0u8; 32];
                let mut final_s = [0u8; 32];

                // Copy bytes with proper padding (right-aligned)
                final_r[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
                final_s[32 - s_bytes.len()..].copy_from_slice(&s_bytes);

                // Combine r and s into final 64-byte signature
                let mut signature = Vec::with_capacity(64);
                signature.extend_from_slice(&final_r);
                signature.extend_from_slice(&final_s);

                let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                    SignerError::SigningFailed("Invalid signature length".to_string())
                })?;

                return Ok(Signature::from(sig_bytes));
            }
        }

        Err(SignerError::SigningFailed(
            "Invalid response from Turnkey API".to_string(),
        ))
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

    /// Create X-Stamp header for Turnkey API authentication
    fn create_stamp(&self, message: &str) -> Result<String, SignerError> {
        let private_key_bytes = hex::decode(&self.api_private_key).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("Failed to decode private key: {e}"))
        })?;

        let private_key_array: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey("Invalid private key length".to_string())
        })?;

        let signing_key = p256::ecdsa::SigningKey::from_slice(&private_key_array)
            .map_err(|e| SignerError::InvalidPrivateKey(format!("Invalid signing key: {e}")))?;

        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature_der = signature.to_der().to_bytes();
        let signature_hex = hex::encode(signature_der);

        let stamp = serde_json::json!({
            "public_key": self.api_public_key,
            "signature": signature_hex,
            "scheme": "SIGNATURE_SCHEME_TK_API_P256"
        });

        let json_stamp = serde_json::to_string(&stamp)?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_stamp.as_bytes()))
    }

    /// Check if Turnkey API is available and credentials are valid
    async fn check_availability(&self) -> bool {
        let request = WhoAmIRequest {
            organization_id: self.organization_id.clone(),
        };

        let body = match serde_json::to_string(&request) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let stamp = match self.create_stamp(&body) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let url = format!("{}/public/v1/query/whoami", self.api_base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Stamp", stamp)
            .body(body)
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for TurnkeySigner {
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
        // Verify Turnkey API is reachable and credentials are valid
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

    // Generate a valid P256 private key for testing
    fn create_test_api_keys() -> (String, String) {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_encoded_point(false).as_bytes());
        (public_key_hex, private_key_hex)
    }

    #[tokio::test]
    async fn test_turnkey_new() {
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        let signer = TurnkeySigner::new(
            api_public_key.clone(),
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        );

        assert!(signer.is_ok());
        let signer = signer.unwrap();
        assert_eq!(signer.organization_id, "test-org-id");
        assert_eq!(signer.private_key_id, "test-key-id");
        assert_eq!(signer.public_key, keypair.pubkey());
    }

    #[tokio::test]
    async fn test_turnkey_new_invalid_pubkey() {
        let (api_public_key, api_private_key) = create_test_api_keys();

        let result = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            "not-a-valid-pubkey".to_string(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_turnkey_pubkey() {
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        let signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();

        assert_eq!(signer.pubkey(), keypair.pubkey());
    }

    #[tokio::test]
    async fn test_turnkey_sign_message() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Create a signature from the keypair
        let message = b"test message";
        let signature = keypair.sign_message(message);
        let sig_bytes = signature.as_ref();

        // Split signature into r and s components (32 bytes each)
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        // Mock the sign endpoint
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "result": {
                        "signRawPayloadResult": {
                            "r": r_hex,
                            "s": s_hex
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(message).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_turnkey_sign_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

        // The signature that Turnkey API will return (signing the message_data)
        let signature = keypair.sign_message(&tx.message_data());
        let sig_bytes = signature.as_ref();

        // Split into r and s
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        // Mock the sign endpoint
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "result": {
                        "signRawPayloadResult": {
                            "r": r_hex,
                            "s": s_hex
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());
        let (serialized_tx, returned_sig) = result.unwrap();

        // Verify the signature matches
        assert_eq!(returned_sig, signature);

        // Verify the transaction is properly serialized
        assert!(!serialized_tx.is_empty());
    }

    #[tokio::test]
    async fn test_turnkey_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Mock 401 Unauthorized response
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Unauthorized"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_turnkey_sign_invalid_response() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Mock response without result field
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_turnkey_sign_invalid_hex() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Mock response with invalid hex
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "result": {
                        "signRawPayloadResult": {
                            "r": "not-valid-hex!!!",
                            "s": "also-not-valid-hex!!!"
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::SerializationError(_)
        ));
    }

    #[tokio::test]
    async fn test_turnkey_is_available() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Mock successful whoami response
        Mock::given(method("POST"))
            .and(path("/public/v1/query/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "organizationId": "test-org-id",
                "organizationName": "Test Org",
                "userId": "test-user-id",
                "username": "test@example.com"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_turnkey_is_not_available() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Mock failed whoami response
        Mock::given(method("POST"))
            .and(path("/public/v1/query/whoami"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_turnkey_create_stamp() {
        let (api_public_key, api_private_key) = create_test_api_keys();
        let keypair = create_test_keypair();

        let signer = TurnkeySigner::new(
            api_public_key.clone(),
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();

        let message = "test message";
        let stamp = signer.create_stamp(message);

        assert!(stamp.is_ok());
        let stamp_str = stamp.unwrap();

        // Verify it's valid base64
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&stamp_str);
        assert!(decoded.is_ok());

        // Verify it's valid JSON
        let json: serde_json::Value = serde_json::from_slice(&decoded.unwrap()).unwrap();
        assert!(json.get("public_key").is_some());
        assert!(json.get("signature").is_some());
        assert_eq!(json.get("scheme").unwrap(), "SIGNATURE_SCHEME_TK_API_P256");
    }

    #[tokio::test]
    async fn test_turnkey_sign_oversized_component() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let (api_public_key, api_private_key) = create_test_api_keys();

        // Create oversized r component (> 32 bytes)
        let r_hex = hex::encode(vec![0xFF; 33]);
        let s_hex = hex::encode(vec![0x01; 32]);

        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "result": {
                        "signRawPayloadResult": {
                            "r": r_hex,
                            "s": s_hex
                        }
                    }
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = TurnkeySigner::new(
            api_public_key,
            api_private_key,
            "test-org-id".to_string(),
            "test-key-id".to_string(),
            keypair.pubkey().to_string(),
        )
        .unwrap();
        signer.api_base_url = mock_server.uri();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }
}
