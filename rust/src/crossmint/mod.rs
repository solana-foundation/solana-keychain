//! Crossmint API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignedTransaction;
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, traits::SolanaSigner};
use base64::Engine;
use std::str::FromStr;
use types::{
    CreateTransactionParams, CreateTransactionRequest, TransactionResponse, WalletResponse,
};

const DEFAULT_BASE_URL: &str = "https://www.crossmint.com/api";
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 60;

/// Configuration for creating a CrossmintSigner
#[derive(Clone)]
pub struct CrossmintSignerConfig {
    pub api_key: String,
    pub wallet_locator: String,
    pub signer: Option<String>,
    pub api_base_url: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_poll_attempts: Option<u32>,
}

/// Crossmint-based signer using Wallets API
#[derive(Clone)]
pub struct CrossmintSigner {
    api_key: String,
    wallet_locator: String,
    signer: Option<String>,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
}

impl std::fmt::Debug for CrossmintSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrossmintSigner")
            .field("public_key", &self.public_key)
            .field("wallet_locator", &self.wallet_locator)
            .finish_non_exhaustive()
    }
}

impl CrossmintSigner {
    /// Create a new Crossmint signer.
    ///
    /// You must call `init()` after construction.
    pub fn new(config: CrossmintSignerConfig) -> Result<Self, SignerError> {
        if config.api_key.is_empty() {
            return Err(SignerError::ConfigError(
                "api_key must not be empty".to_string(),
            ));
        }
        if config.wallet_locator.is_empty() {
            return Err(SignerError::ConfigError(
                "wallet_locator must not be empty".to_string(),
            ));
        }

        let api_base_url = config
            .api_base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        if !api_base_url.starts_with("https://") {
            return Err(SignerError::ConfigError(
                "api_base_url must use HTTPS".to_string(),
            ));
        }

        let poll_interval_ms = config.poll_interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS);
        if poll_interval_ms == 0 {
            return Err(SignerError::ConfigError(
                "poll_interval_ms must be greater than 0".to_string(),
            ));
        }

        let max_poll_attempts = config
            .max_poll_attempts
            .unwrap_or(DEFAULT_MAX_POLL_ATTEMPTS);
        if max_poll_attempts == 0 {
            return Err(SignerError::ConfigError(
                "max_poll_attempts must be greater than 0".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            api_key: config.api_key,
            wallet_locator: config.wallet_locator,
            signer: config.signer,
            api_base_url,
            client,
            public_key: Pubkey::default(),
            poll_interval_ms,
            max_poll_attempts,
        })
    }

    /// Initialize signer by resolving wallet details and signer public key.
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.fetch_wallet().await?;

        if !wallet.chain_type.eq_ignore_ascii_case("solana") {
            return Err(SignerError::ConfigError(format!(
                "Expected Solana wallet, got chainType={}",
                wallet.chain_type
            )));
        }

        if !wallet.wallet_type.eq_ignore_ascii_case("smart")
            && !wallet.wallet_type.eq_ignore_ascii_case("mpc")
        {
            return Err(SignerError::ConfigError(format!(
                "Unsupported Crossmint wallet type: {}",
                wallet.wallet_type
            )));
        }

        self.public_key = Pubkey::from_str(&wallet.address).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid Solana public key returned by Crossmint wallet".to_string(),
            )
        })?;

        Ok(())
    }

    async fn fetch_wallet(&self) -> Result<WalletResponse, SignerError> {
        let url = format!(
            "{}/2025-06-09/wallets/{}",
            self.api_base_url, self.wallet_locator
        );

        let response = self
            .client
            .get(&url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "address", "fetch_wallet").await
    }

    async fn create_transaction(
        &self,
        transaction: String,
    ) -> Result<TransactionResponse, SignerError> {
        let url = format!(
            "{}/2025-06-09/wallets/{}/transactions",
            self.api_base_url, self.wallet_locator
        );

        let request = CreateTransactionRequest {
            params: CreateTransactionParams {
                transaction,
                signer: self.signer.clone(),
            },
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-API-KEY", &self.api_key)
            .json(&request)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "id", "create_transaction").await
    }

    async fn get_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<TransactionResponse, SignerError> {
        let url = format!(
            "{}/2025-06-09/wallets/{}/transactions/{}",
            self.api_base_url, self.wallet_locator, transaction_id
        );

        let response = self
            .client
            .get(&url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "id", "get_transaction").await
    }

    async fn parse_response_with_required_field<T>(
        response: reqwest::Response,
        required_field: &str,
        context: &str,
    ) -> Result<T, SignerError>
    where
        T: serde::de::DeserializeOwned,
    {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        let value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);

        if status >= 400 {
            let message = Self::extract_error_message(&value)
                .unwrap_or_else(|| format!("Crossmint API error {status}"));
            return Err(SignerError::RemoteApiError(format!("{context}: {message}")));
        }

        if value.get(required_field).is_none() {
            if let Some(message) = Self::extract_error_message(&value) {
                return Err(SignerError::RemoteApiError(format!("{context}: {message}")));
            }

            return Err(SignerError::SerializationError(format!(
                "{context}: missing expected field '{required_field}' in response"
            )));
        }

        serde_json::from_value(value).map_err(|e| {
            SignerError::SerializationError(format!(
                "{context}: failed to parse JSON response: {e}"
            ))
        })
    }

    fn extract_error_message(value: &serde_json::Value) -> Option<String> {
        if let Some(message) = value.get("message").and_then(|m| m.as_str()) {
            return Some(message.to_string());
        }

        if let Some(error_str) = value.get("error").and_then(|e| e.as_str()) {
            return Some(error_str.to_string());
        }

        if let Some(error_obj) = value.get("error").and_then(|e| e.as_object()) {
            if let Some(message) = error_obj.get("message").and_then(|m| m.as_str()) {
                return Some(message.to_string());
            }
        }

        None
    }

    async fn poll_transaction(
        &self,
        mut response: TransactionResponse,
    ) -> Result<TransactionResponse, SignerError> {
        for _ in 0..self.max_poll_attempts {
            match response.status.as_str() {
                "success" => return Ok(response),
                "failed" => {
                    let detail = response
                        .error
                        .as_ref()
                        .map(serde_json::Value::to_string)
                        .unwrap_or_else(|| "unknown error".to_string());
                    return Err(SignerError::SigningFailed(format!(
                        "Crossmint transaction failed: {detail}"
                    )));
                }
                "awaiting-approval" => {
                    return Err(SignerError::SigningFailed(
                        "Crossmint transaction is awaiting approval; additional signer approvals are required".to_string(),
                    ));
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms))
                        .await;
                    response = self.get_transaction(&response.id).await?;
                }
            }
        }

        Err(SignerError::RemoteApiError(format!(
            "Crossmint transaction polling timed out after {} attempts",
            self.max_poll_attempts
        )))
    }

    fn decode_signature(signature_str: &str) -> Option<Signature> {
        Self::decode_base58_signature(signature_str)
            .or_else(|| Self::decode_hex_signature(signature_str))
            .or_else(|| Self::decode_base64_signature(signature_str))
    }

    fn decode_base58_signature(signature_str: &str) -> Option<Signature> {
        let bytes = bs58::decode(signature_str).into_vec().ok()?;
        let sig_bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Signature::from(sig_bytes))
    }

    fn decode_hex_signature(signature_str: &str) -> Option<Signature> {
        let clean = signature_str.strip_prefix("0x").unwrap_or(signature_str);
        if clean.len() != 128 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }

        let mut bytes = Vec::with_capacity(64);
        for i in (0..clean.len()).step_by(2) {
            let byte = u8::from_str_radix(&clean[i..i + 2], 16).ok()?;
            bytes.push(byte);
        }

        let sig_bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Signature::from(sig_bytes))
    }

    fn decode_base64_signature(signature_str: &str) -> Option<Signature> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_str)
            .ok()?;
        let sig_bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Signature::from(sig_bytes))
    }

    fn extract_signature_from_serialized_transaction(
        &self,
        serialized_transaction: &str,
    ) -> Result<Signature, SignerError> {
        let bytes = bs58::decode(serialized_transaction)
            .into_vec()
            .map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to decode Crossmint onChain.transaction as base58: {e}"
                ))
            })?;

        let transaction: Transaction = bincode::deserialize(&bytes).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to deserialize Crossmint onChain.transaction: {e}"
            ))
        })?;

        let position =
            TransactionUtil::get_signing_keypair_position(&transaction, &self.public_key).map_err(
                |e| {
                    SignerError::SigningFailed(format!(
                        "Failed to locate signer pubkey in Crossmint transaction: {e}"
                    ))
                },
            )?;

        transaction
            .signatures
            .get(position)
            .copied()
            .filter(|sig| *sig != Signature::default())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint onChain.transaction did not contain a signer signature".to_string(),
                )
            })
    }

    fn extract_signature_from_response(
        &self,
        response: &TransactionResponse,
    ) -> Result<Signature, SignerError> {
        if let Some(on_chain) = &response.on_chain {
            if let Some(serialized_transaction) = &on_chain.transaction {
                if let Ok(signature) =
                    self.extract_signature_from_serialized_transaction(serialized_transaction)
                {
                    return Ok(signature);
                }
            }

            if let Some(tx_id) = &on_chain.tx_id {
                if let Some(signature) = Self::decode_base58_signature(tx_id) {
                    return Ok(signature);
                }
            }
        }

        if let Some(approvals) = &response.approvals {
            for submitted in &approvals.submitted {
                if let Some(signature_str) = &submitted.signature {
                    if let Some(signature) = Self::decode_signature(signature_str) {
                        return Ok(signature);
                    }
                }
            }
        }

        Err(SignerError::SigningFailed(
            "Unable to extract signature from Crossmint transaction response".to_string(),
        ))
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        if self.public_key == Pubkey::default() {
            return Err(SignerError::ConfigError(
                "Signer not initialized. Call init() first.".to_string(),
            ));
        }

        let serialized = bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;
        let transaction_b58 = bs58::encode(serialized).into_string();

        let create_response = self.create_transaction(transaction_b58).await?;
        let final_response = self.poll_transaction(create_response).await?;
        let signature = self.extract_signature_from_response(&final_response)?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    async fn check_availability(&self) -> bool {
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, self.fetch_wallet()).await;
        matches!(result, Ok(Ok(_)))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for CrossmintSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::SigningFailed(
            "Crossmint sign_message is not supported for Solana wallets in this signer".to_string(),
        ))
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
    use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
    use crate::test_util::create_test_transaction;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn wallet_response(address: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chainType": "solana",
            "type": "smart",
            "address": address
        }))
    }

    #[tokio::test]
    async fn test_init_success() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let address = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&address))
            .mount(&server)
            .await;

        let mut signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer: None,
            api_base_url: Some(server.uri()),
            poll_interval_ms: None,
            max_poll_attempts: None,
        })
        .unwrap();

        signer.init().await.unwrap();
        assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
    }

    #[tokio::test]
    async fn test_sign_message_not_supported() {
        let signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer: None,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
        })
        .unwrap();

        let result = signer.sign_message(b"hello").await;
        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("not supported"),
            "Expected not supported error"
        );
    }

    #[tokio::test]
    async fn test_sign_transaction_success() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer_pubkey = keypair_pubkey(&keypair);
        let signer_address = signer_pubkey.to_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_address))
            .mount(&server)
            .await;

        let mut signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer: None,
            api_base_url: Some(server.uri()),
            poll_interval_ms: Some(1),
            max_poll_attempts: Some(2),
        })
        .unwrap();
        signer.init().await.unwrap();

        let mut signed_remote_tx = create_test_transaction(&signer_pubkey);
        let expected_signature = keypair_sign_message(&keypair, &signed_remote_tx.message_data());
        TransactionUtil::add_signature_to_transaction(
            &mut signed_remote_tx,
            &signer_pubkey,
            expected_signature,
        )
        .unwrap();

        let on_chain_transaction =
            bs58::encode(bincode::serialize(&signed_remote_tx).unwrap()).into_string();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "success",
                "chainType": "solana",
                "walletType": "smart",
                "onChain": {
                    "transaction": on_chain_transaction
                }
            })))
            .mount(&server)
            .await;

        let mut local_tx = create_test_transaction(&signer_pubkey);
        let (serialized, signature) = signer.sign_transaction(&mut local_tx).await.unwrap();

        assert_eq!(signature, expected_signature);
        assert!(!serialized.is_empty());
    }

    #[tokio::test]
    async fn test_sign_transaction_awaiting_approval() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer_address = keypair_pubkey(&keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_address))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "awaiting-approval",
                "chainType": "solana",
                "walletType": "smart"
            })))
            .mount(&server)
            .await;

        let mut signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer: None,
            api_base_url: Some(server.uri()),
            poll_interval_ms: Some(1),
            max_poll_attempts: Some(2),
        })
        .unwrap();
        signer.init().await.unwrap();

        let mut tx = create_test_transaction(&signer.pubkey());
        let result = signer.sign_transaction(&mut tx).await;

        assert!(result.is_err());
        assert!(
            format!("{}", result.unwrap_err()).contains("awaiting approval"),
            "Expected awaiting approval error"
        );
    }
}
