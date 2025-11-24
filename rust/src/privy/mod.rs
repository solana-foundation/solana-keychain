//! Privy API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignedTransaction;
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, traits::SolanaSigner};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::str::FromStr;
use types::{SignMessageParams, SignMessageRequest, SignMessageResponse, WalletResponse};

/// Privy-based signer using Privy's wallet API
#[derive(Clone)]
pub struct PrivySigner {
    app_id: String,
    app_secret: String,
    wallet_id: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
}

impl std::fmt::Debug for PrivySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivySigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl PrivySigner {
    /// Create a new PrivySigner
    ///
    /// # Arguments
    ///
    /// * `app_id` - Privy application ID
    /// * `app_secret` - Privy application secret
    /// * `wallet_id` - Privy wallet ID
    pub fn new(app_id: String, app_secret: String, wallet_id: String) -> Self {
        Self {
            app_id,
            app_secret,
            wallet_id,
            api_base_url: "https://api.privy.io/v1".to_string(),
            client: reqwest::Client::new(),
            // Set the public key to default to indicate that it's not initialized
            public_key: Pubkey::default(),
        }
    }

    /// Initialize the signer by fetching the public key
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let pubkey = self.fetch_public_key().await?;
        self.public_key = pubkey;
        Ok(())
    }

    /// Get the Basic Auth header value
    fn get_privy_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.app_id, self.app_secret);
        format!("Basic {}", STANDARD.encode(credentials))
    }

    /// Fetch the public key from Privy API
    async fn fetch_public_key(&self) -> Result<Pubkey, SignerError> {
        let url = format!("{}/wallets/{}", self.api_base_url, self.wallet_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.get_privy_auth_header())
            .header("privy-app-id", &self.app_id)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "Privy API get_public_key error - status: {status}, response: {error_text}"
            );

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Privy API get_public_key error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let wallet_info: WalletResponse = response.json().await?;

        // For Solana wallets, the address is the public key
        Pubkey::from_str(&wallet_info.address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid public key from Privy API".to_string())
        })
    }

    /// Sign message bytes using Privy API
    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        let url = format!("{}/wallets/{}/rpc", self.api_base_url, self.wallet_id);

        let request = SignMessageRequest {
            method: "signMessage",
            params: SignMessageParams {
                message: STANDARD.encode(serialized),
                encoding: "base64",
            },
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", self.get_privy_auth_header())
            .header("privy-app-id", &self.app_id)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Privy API sign_message error - status: {status}, response: {error_text}");

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Privy API sign_message error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let response_text = response.text().await?;
        let sign_response: SignMessageResponse = serde_json::from_str(&response_text)?;

        let decoded_response = STANDARD
            .decode(&sign_response.data.signature)
            .expect("Failed to decode response");

        let signature = Signature::try_from(decoded_response.as_slice())
            .map_err(|_| SignerError::SigningFailed("Failed to parse signature".to_string()))?;

        Ok(signature)
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
}

#[async_trait::async_trait]
impl SolanaSigner for PrivySigner {
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
        // Check if public key is initialized
        self.public_key != Pubkey::default()
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

    #[tokio::test]
    async fn test_privy_new() {
        let signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );

        assert_eq!(signer.app_id, "test-app-id");
        assert_eq!(signer.wallet_id, "test-wallet-id");
        assert_eq!(signer.public_key, Pubkey::default());
    }

    #[tokio::test]
    async fn test_privy_fetch_public_key() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey_str = keypair.pubkey().to_string();

        // Mock the wallet GET endpoint
        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .and(header(
                "Authorization",
                "Basic dGVzdC1hcHAtaWQ6dGVzdC1hcHAtc2VjcmV0",
            )) // base64("test-app-id:test-app-secret")
            .and(header("privy-app-id", "test-app-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": pubkey_str,
                "chain_type": "solana"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();

        let result = signer.init().await;
        assert!(result.is_ok());
        assert_eq!(signer.pubkey(), keypair.pubkey());
    }

    #[tokio::test]
    async fn test_privy_sign_message() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Create a signed transaction
        let tx = create_test_transaction(&keypair_pubkey(&keypair));
        let signature = keypair.sign_message(&tx.message_data());

        let mut signed_tx = tx.clone();
        signed_tx.signatures = vec![signature];

        // Mock the RPC signing endpoint
        Mock::given(method("POST"))
            .and(path("/wallets/test-wallet-id/rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "signMessage",
                "data": {
                    "signature": STANDARD.encode(signature),
                    "encoding": "base64"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();
        signer.public_key = keypair.pubkey();

        let result = signer.sign_message(&tx.message_data()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_privy_sign_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        let mut tx = create_test_transaction(&keypair_pubkey(&keypair));

        // The signature that Privy API will return (signing the message_data)
        let signature = keypair.sign_message(&tx.message_data());

        // Create a signed transaction to return from the mock
        let mut signed_tx = tx.clone();
        signed_tx.signatures = vec![signature];

        // Mock the RPC signing endpoint - it returns the signed transaction
        Mock::given(method("POST"))
            .and(path("/wallets/test-wallet-id/rpc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "method": "signMessage",
                "data": {
                    "signature": STANDARD.encode(signature),
                    "encoding": "base64"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();
        signer.public_key = keypair.pubkey();

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok());
        let (serialized_tx, returned_sig) = result.unwrap();

        // Verify the signature matches
        assert_eq!(returned_sig, signature);

        // Verify the transaction is properly serialized
        assert!(!serialized_tx.is_empty());
    }

    #[tokio::test]
    async fn test_privy_pubkey() {
        let keypair = create_test_keypair();
        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.public_key = keypair.pubkey();

        assert_eq!(signer.pubkey(), keypair.pubkey());
    }

    #[tokio::test]
    async fn test_privy_fetch_public_key_unauthorized() {
        let mock_server = MockServer::start().await;

        // Mock 401 Unauthorized response
        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Unauthorized"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "bad-app-id".to_string(),
            "bad-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();

        let result = signer.init().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_privy_fetch_public_key_invalid() {
        let mock_server = MockServer::start().await;

        // Mock response with invalid public key
        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "address": "not-a-valid-pubkey",
                "chain_type": "solana"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();

        let result = signer.init().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_privy_sign_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();

        // Mock 401 Unauthorized response
        Mock::given(method("POST"))
            .and(path("/wallets/test-wallet-id/rpc"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Unauthorized"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut signer = PrivySigner::new(
            "bad-app-id".to_string(),
            "bad-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.api_base_url = mock_server.uri();
        signer.public_key = keypair.pubkey();

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_privy_is_available() {
        let keypair = create_test_keypair();

        // Not initialized
        let signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        assert!(!signer.is_available().await);

        // Initialized
        let mut signer = PrivySigner::new(
            "test-app-id".to_string(),
            "test-app-secret".to_string(),
            "test-wallet-id".to_string(),
        );
        signer.public_key = keypair.pubkey();
        assert!(signer.is_available().await);
    }
}
