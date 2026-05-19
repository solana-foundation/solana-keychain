mod auth;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignTransactionResult;
pub use crate::traits::SignedTransaction;
use crate::{
    error::SignerError, http_client_config::HttpClientConfig,
    signature_util::EXPECTED_SIGNATURE_LENGTH, traits::SolanaSigner,
    transaction_util::TransactionUtil,
};
use types::{GenerateSignatureRequest, GenerateSignatureResponse, GetWalletResponse};

/// Dfns-based signer using Dfns Keys API
#[derive(Clone)]
pub struct DfnsSigner {
    auth_token: String,
    cred_id: String,
    private_key_pem: String,
    wallet_id: String,
    key_id: String,
    public_key: Pubkey,
    api_base_url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for DfnsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DfnsSigner")
            .field("public_key", &self.public_key)
            .field("wallet_id", &self.wallet_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Configuration for creating a DfnsSigner
#[derive(Clone)]
pub struct DfnsSignerConfig {
    /// Service account token or personal access token
    pub auth_token: String,
    /// Credential ID for user action signing
    pub cred_id: String,
    /// Private key in PEM format for signing user action challenges (Ed25519, P256, or RSA)
    pub private_key_pem: String,
    /// Dfns wallet ID
    pub wallet_id: String,
    /// API base URL (default: "https://api.dfns.io")
    pub api_base_url: Option<String>,
    /// Optional HTTP client timeout config.
    pub http_client_config: Option<HttpClientConfig>,
}

impl DfnsSigner {
    /// Create a new DfnsSigner.
    ///
    /// You must call `init()` after construction to fetch the public key from Dfns.
    pub fn new(config: DfnsSignerConfig) -> Self {
        Self::from_config(config)
    }

    /// Create a new DfnsSigner from a configuration object.
    pub fn from_config(config: DfnsSignerConfig) -> Self {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let builder = reqwest::Client::builder().user_agent("solana-keychain");
        let builder = builder
            .timeout(http_client_config.resolved_request_timeout())
            .connect_timeout(http_client_config.resolved_connect_timeout())
            .https_only(true);
        let client = builder.build().expect("Failed to build HTTP client");

        Self {
            auth_token: config.auth_token,
            cred_id: config.cred_id,
            private_key_pem: config.private_key_pem,
            wallet_id: config.wallet_id,
            key_id: String::new(),
            public_key: Pubkey::default(),
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.dfns.io".to_string()),
            client,
        }
    }

    /// Initialize the signer by fetching the wallet and extracting key details from Dfns
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.get_wallet().await?;

        if wallet.status != "Active" {
            return Err(SignerError::ConfigError(format!(
                "Wallet is not active: {}",
                wallet.status
            )));
        }

        if wallet.signing_key.scheme != "EdDSA" {
            return Err(SignerError::ConfigError(format!(
                "Unsupported key scheme: {} (expected EdDSA)",
                wallet.signing_key.scheme
            )));
        }

        if wallet.signing_key.curve != "ed25519" {
            return Err(SignerError::ConfigError(format!(
                "Unsupported key curve: {} (expected ed25519)",
                wallet.signing_key.curve
            )));
        }

        let pubkey_bytes = hex::decode(&wallet.signing_key.public_key).map_err(|e| {
            SignerError::InvalidPublicKey(format!("Failed to decode hex public key: {e}"))
        })?;

        self.public_key = Pubkey::try_from(pubkey_bytes.as_slice()).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid public key length (expected 32 bytes)".to_string(),
            )
        })?;

        self.key_id = wallet.signing_key.id;

        Ok(())
    }

    /// Fetch wallet details from Dfns
    async fn get_wallet(&self) -> Result<GetWalletResponse, SignerError> {
        let url = format!("{}/wallets/{}", self.api_base_url, self.wallet_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();

            #[cfg(feature = "unsafe-debug")]
            {
                let _error_text = response.text().await.unwrap_or_default();
                log::error!("Dfns get_wallet error - status: {status}, response: {_error_text}");
            }

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Dfns get_wallet error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        response.json().await.map_err(|e| {
            SignerError::SerializationError(format!("Failed to parse wallet response: {e}"))
        })
    }

    /// Send a signature request to the Dfns Keys API
    async fn send_signature_request(
        &self,
        request_body: GenerateSignatureRequest,
    ) -> Result<Signature, SignerError> {
        let http_path = format!("/keys/{}/signatures", self.key_id);
        let body_json = serde_json::to_string(&request_body)?;

        let user_action = auth::sign_user_action(
            &self.client,
            &self.api_base_url,
            &self.auth_token,
            &self.cred_id,
            &self.private_key_pem,
            "POST",
            &http_path,
            &body_json,
        )
        .await?;

        let url = format!("{}{}", self.api_base_url, http_path);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("Content-Type", "application/json")
            .header("x-dfns-useraction", &user_action)
            .body(body_json)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();

            #[cfg(feature = "unsafe-debug")]
            {
                let _error_text = response.text().await.unwrap_or_default();
                log::error!(
                    "Dfns generate_signature error - status: {status}, response: {_error_text}"
                );
            }

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Dfns generate_signature error - status: {status}");

            return Err(SignerError::RemoteApiError(format!("API error {status}")));
        }

        let sig_response: GenerateSignatureResponse = response.json().await.map_err(|e| {
            SignerError::SerializationError(format!("Failed to parse signature response: {e}"))
        })?;

        if sig_response.status == "Failed" {
            return Err(SignerError::SigningFailed(
                "Dfns signing failed".to_string(),
            ));
        }

        if sig_response.status != "Signed" {
            return Err(SignerError::SigningFailed(format!(
                "Unexpected signature status: {} (may require policy approval)",
                sig_response.status
            )));
        }

        let components = sig_response.signature.ok_or_else(|| {
            SignerError::SigningFailed("Signature components missing from response".to_string())
        })?;

        self.combine_signature(&components.r, &components.s)
    }

    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let request = GenerateSignatureRequest::Message {
            message: format!("0x{}", hex::encode(message)),
        };
        let sig = self.send_signature_request(request).await?;

        if !sig.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    async fn sign_transaction_bytes(
        &self,
        transaction: &Transaction,
    ) -> Result<Signature, SignerError> {
        let tx_bytes = bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;
        let request = GenerateSignatureRequest::Transaction {
            transaction: format!("0x{}", hex::encode(&tx_bytes)),
            blockchain_kind: "Solana".to_string(),
        };
        let sig = self.send_signature_request(request).await?;

        if !sig.verify(&self.public_key.to_bytes(), &transaction.message_data()) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

        Ok(sig)
    }

    fn combine_signature(&self, r: &str, s: &str) -> Result<Signature, SignerError> {
        let r_bytes = hex::decode(r.strip_prefix("0x").unwrap_or(r)).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode signature r: {e}"))
        })?;
        let s_bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode signature s: {e}"))
        })?;

        let mut sig_bytes = Vec::with_capacity(EXPECTED_SIGNATURE_LENGTH);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);

        let sig_array: [u8; EXPECTED_SIGNATURE_LENGTH] = sig_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed(format!(
                "Invalid signature length (expected {} bytes)",
                EXPECTED_SIGNATURE_LENGTH
            ))
        })?;

        Ok(Signature::from(sig_array))
    }

    /// Sign and serialize a transaction
    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_transaction_bytes(transaction).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if Dfns API is available by fetching wallet details
    async fn check_availability(&self) -> bool {
        self.get_wallet().await.is_ok()
    }
}

#[async_trait::async_trait]
impl SolanaSigner for DfnsSigner {
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
    use crate::dfns::auth::tests::TEST_ED25519_PEM;
    use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer};
    use crate::test_util::create_test_transaction;
    use std::str::FromStr;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_KEY_ID: &str = "test-key-id";
    const TEST_PUBKEY_HEX: &str =
        "5da30b28c87836b0ee76ae7b07e3a2e3be1a4c12e48fce3aee18de0a13040b9a";
    // This is the base58 encoding of the above hex bytes
    const TEST_PUBKEY: &str = "7JX7XMJ9TpfkKmz5u85DowRFyQabHsUgWajTmhToUfgM";

    fn create_test_signer_uninit(base_url: &str) -> DfnsSigner {
        DfnsSigner {
            auth_token: "test-auth-token".to_string(),
            cred_id: "test-cred-id".to_string(),
            private_key_pem: TEST_ED25519_PEM.to_string(),
            wallet_id: "test-wallet-id".to_string(),
            key_id: String::new(),
            public_key: Pubkey::default(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn create_test_signer(base_url: &str) -> DfnsSigner {
        DfnsSigner {
            auth_token: "test-auth-token".to_string(),
            cred_id: "test-cred-id".to_string(),
            private_key_pem: TEST_ED25519_PEM.to_string(),
            wallet_id: "test-wallet-id".to_string(),
            key_id: TEST_KEY_ID.to_string(),
            public_key: Pubkey::from_str(TEST_PUBKEY).unwrap(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn wallet_response_json() -> serde_json::Value {
        serde_json::json!({
            "id": "test-wallet-id",
            "status": "Active",
            "network": "Solana",
            "signingKey": {
                "id": TEST_KEY_ID,
                "scheme": "EdDSA",
                "curve": "ed25519",
                "publicKey": TEST_PUBKEY_HEX
            }
        })
    }

    #[test]
    fn test_new_valid() {
        let signer = DfnsSigner::new(DfnsSignerConfig {
            auth_token: "token".to_string(),
            cred_id: "cred".to_string(),
            private_key_pem: TEST_ED25519_PEM.to_string(),
            wallet_id: "wallet".to_string(),
            api_base_url: None,
            http_client_config: None,
        });
        assert_eq!(signer.api_base_url, "https://api.dfns.io");
        assert_eq!(signer.public_key, Pubkey::default());
    }

    #[tokio::test]
    async fn test_init_success() {
        let mock_server = MockServer::start().await;
        let mut signer = create_test_signer_uninit(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(wallet_response_json()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.init().await;
        assert!(result.is_ok());
        assert_eq!(signer.pubkey().to_string(), TEST_PUBKEY);
        assert_eq!(signer.key_id, TEST_KEY_ID);
    }

    #[tokio::test]
    async fn test_init_api_error() {
        let mock_server = MockServer::start().await;
        let mut signer = create_test_signer_uninit(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_init_invalid_scheme() {
        let mock_server = MockServer::start().await;
        let mut signer = create_test_signer_uninit(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-wallet-id",
                "status": "Active",
                "network": "Ethereum",
                "signingKey": {
                    "id": "key-id",
                    "scheme": "ECDSA",
                    "curve": "secp256k1",
                    "publicKey": "abcd"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();
        let message = b"test message";
        let signature = keypair.sign_message(message);
        let sig_bytes = signature.as_ref();
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = keypair_pubkey(&keypair);

        // Mock user action init
        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "test-challenge",
                "challengeIdentifier": "test-challenge-id",
                "allowCredentials": {
                    "key": [{ "id": "test-cred-id" }]
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock user action sign
        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "test-user-action-token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock generate signature via Keys API
        Mock::given(method("POST"))
            .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
            .and(header("x-dfns-useraction", "test-user-action-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sig-123",
                "status": "Signed",
                "signature": {
                    "r": r_hex,
                    "s": s_hex
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), signature);
    }

    #[tokio::test]
    async fn test_sign_message_signature_verification_failure() {
        let mock_server = MockServer::start().await;
        let signing_keypair = Keypair::new();
        let different_keypair = Keypair::new();
        let message = b"test message";
        let signature = signing_keypair.sign_message(message);
        let sig_bytes = signature.as_ref();
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = keypair_pubkey(&different_keypair);

        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "test-challenge",
                "challengeIdentifier": "test-challenge-id",
                "allowCredentials": {
                    "key": [{ "id": "test-cred-id" }]
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "test-user-action-token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
            .and(header("x-dfns-useraction", "test-user-action-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sig-123",
                "status": "Signed",
                "signature": {
                    "r": r_hex,
                    "s": s_hex
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_sign_message_api_error() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        // Mock user action init
        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "test-challenge",
                "challengeIdentifier": "test-challenge-id",
                "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Signing endpoint fails
        Mock::given(method("POST"))
            .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = Keypair::new();

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = keypair_pubkey(&keypair);

        let mut transaction = create_test_transaction(&signer.pubkey());
        let signature = keypair.sign_message(&transaction.message_data());
        let sig_bytes = signature.as_ref();
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        // Mock user action flow
        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "test-challenge",
                "challengeIdentifier": "test-challenge-id",
                "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "test-user-action-token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sig-456",
                "status": "Signed",
                "signature": {
                    "r": r_hex,
                    "s": s_hex
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut transaction).await;
        assert!(result.is_ok());
        let (_, returned_sig) = result.unwrap().into_signed_transaction();
        assert_eq!(returned_sig, signature);
    }

    #[tokio::test]
    async fn test_sign_transaction_signature_verification_failure() {
        let mock_server = MockServer::start().await;
        let signing_keypair = Keypair::new();
        let different_keypair = Keypair::new();

        let mut signer = create_test_signer(&mock_server.uri());
        signer.public_key = keypair_pubkey(&different_keypair);

        let mut transaction = create_test_transaction(&signer.pubkey());
        let signature = signing_keypair.sign_message(&transaction.message_data());
        let sig_bytes = signature.as_ref();
        let r_hex = hex::encode(&sig_bytes[0..32]);
        let s_hex = hex::encode(&sig_bytes[32..64]);

        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "test-challenge",
                "challengeIdentifier": "test-challenge-id",
                "allowCredentials": { "key": [{ "id": "test-cred-id" }] }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "test-user-action-token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/keys/{}/signatures", TEST_KEY_ID)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sig-456",
                "status": "Signed",
                "signature": {
                    "r": r_hex,
                    "s": s_hex
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_transaction(&mut transaction).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_is_available_success() {
        let mock_server = MockServer::start().await;
        let signer = create_test_signer(&mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(wallet_response_json()))
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
            .and(path("/wallets/test-wallet-id"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }
}
