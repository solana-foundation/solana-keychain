//! Crossmint API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, traits::SolanaSigner};
use std::str::FromStr;
use types::{
    CreateTransactionParams, CreateTransactionRequest, TransactionResponse, WalletResponse,
};

const DEFAULT_BASE_URL: &str = "https://www.crossmint.com/api";
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 60;
const TEST_SIGNER_DERIVED_PUBKEY_ENV: &str = "TEST_CROSSMINT_SIGNER_DERIVED_PUBKEY";

/// Configuration for creating a CrossmintSigner
#[derive(Clone)]
pub struct CrossmintSignerConfig {
    pub api_key: String,
    pub wallet_locator: String,
    /// Optional server signer secret (`xmsk1_<64hex>`). When provided, the signer
    /// derives an Ed25519 keypair via HKDF and automatically signs any
    /// `awaiting-approval` transactions from the Crossmint API.
    pub signer_secret: Option<String>,
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
    signing_key: Option<ed25519_dalek::SigningKey>,
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

        let (signing_key, signer) = if let Some(secret) = &config.signer_secret {
            let key = Self::derive_signing_key(secret, &config.api_key)?;
            let pubkey_b58 = bs58::encode(key.verifying_key().as_bytes()).into_string();
            let locator = config
                .signer
                .clone()
                .unwrap_or_else(|| format!("server:{pubkey_b58}"));
            (Some(key), Some(locator))
        } else {
            (None, config.signer)
        };

        Ok(Self {
            api_key: config.api_key,
            wallet_locator: config.wallet_locator,
            signer,
            api_base_url,
            client,
            public_key: Pubkey::default(),
            poll_interval_ms,
            max_poll_attempts,
            signing_key,
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

        let mut resolved_pubkey = Pubkey::from_str(&wallet.address).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid Solana public key returned by Crossmint wallet".to_string(),
            )
        })?;

        if let Some(test_pubkey) = Self::resolve_test_signer_pubkey_override()? {
            resolved_pubkey = test_pubkey;
        }

        self.public_key = resolved_pubkey;

        Ok(())
    }

    fn resolve_test_signer_pubkey_override() -> Result<Option<Pubkey>, SignerError> {
        if !cfg!(any(test, feature = "integration-tests")) {
            return Ok(None);
        }

        let raw_pubkey = std::env::var(TEST_SIGNER_DERIVED_PUBKEY_ENV).ok();
        Self::parse_test_signer_pubkey_override(raw_pubkey.as_deref())
    }

    fn parse_test_signer_pubkey_override(
        raw_pubkey: Option<&str>,
    ) -> Result<Option<Pubkey>, SignerError> {
        let Some(raw_pubkey) = raw_pubkey.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };

        let pubkey = Pubkey::from_str(raw_pubkey).map_err(|_| {
            SignerError::ConfigError(format!(
                "{TEST_SIGNER_DERIVED_PUBKEY_ENV} must be a valid Solana public key"
            ))
        })?;
        Ok(Some(pubkey))
    }

    fn debug_signatures_enabled() -> bool {
        std::env::var("CROSSMINT_DEBUG_SIGNATURES").as_deref() == Ok("1")
    }

    async fn fetch_wallet(&self) -> Result<WalletResponse, SignerError> {
        let url = self.build_wallets_api_url(&[])?;

        let response = self
            .client
            .get(url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "address", "fetch_wallet").await
    }

    async fn create_transaction(
        &self,
        transaction: String,
    ) -> Result<TransactionResponse, SignerError> {
        let url = self.build_wallets_api_url(&["transactions"])?;

        let request = CreateTransactionRequest {
            params: CreateTransactionParams {
                transaction,
                signer: self.signer.clone(),
            },
        };

        let response = self
            .client
            .post(url)
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
        let url = self.build_wallets_api_url(&["transactions", transaction_id])?;

        let response = self
            .client
            .get(url)
            .header("X-API-KEY", &self.api_key)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "id", "get_transaction").await
    }

    fn build_wallets_api_url(&self, segments: &[&str]) -> Result<String, SignerError> {
        let base = reqwest::Url::parse(&self.api_base_url)
            .map_err(|e| SignerError::ConfigError(format!("Invalid api_base_url: {e}")))?;
        if base.cannot_be_a_base() {
            return Err(SignerError::ConfigError(
                "api_base_url cannot be used as a base URL".to_string(),
            ));
        }

        let mut url = base.as_str().trim_end_matches('/').to_string();
        url.push_str("/2025-06-09/wallets/");
        url.push_str(&Self::encode_uri_component(&self.wallet_locator));
        for segment in segments {
            url.push('/');
            url.push_str(&Self::encode_uri_component(segment));
        }

        Ok(url)
    }

    fn encode_uri_component(input: &str) -> String {
        let mut encoded = String::with_capacity(input.len());
        for byte in input.bytes() {
            if matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'!'
                    | b'~'
                    | b'*'
                    | b'\''
                    | b'('
                    | b')'
            ) {
                encoded.push(byte as char);
            } else {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
        encoded
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
                    response = self.handle_awaiting_approval(response).await?;
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms))
                        .await;
                    response = self.get_transaction(&response.id).await?;
                }
            }
        }

        match response.status.as_str() {
            "success" => Ok(response),
            "failed" => {
                let detail = response
                    .error
                    .as_ref()
                    .map(serde_json::Value::to_string)
                    .unwrap_or_else(|| "unknown error".to_string());
                Err(SignerError::SigningFailed(format!(
                    "Crossmint transaction failed: {detail}"
                )))
            }
            "awaiting-approval" => Err(SignerError::SigningFailed(
                "Crossmint transaction is awaiting approval; additional signer approvals are required"
                    .to_string(),
            )),
            _ => Err(SignerError::RemoteApiError(format!(
                "Crossmint transaction polling timed out after {} attempts",
                self.max_poll_attempts
            ))),
        }
    }

    async fn handle_awaiting_approval(
        &self,
        response: TransactionResponse,
    ) -> Result<TransactionResponse, SignerError> {
        let (Some(signing_key), Some(signer_locator)) = (&self.signing_key, &self.signer) else {
            return Err(SignerError::SigningFailed(
                "Crossmint transaction is awaiting approval; additional signer approvals are required".to_string(),
            ));
        };

        let message = response
            .approvals
            .as_ref()
            .and_then(|a| a.pending.first())
            .and_then(|p| p.message.as_deref())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint transaction awaiting approval but no pending message found"
                        .to_string(),
                )
            })?;

        self.submit_approval(&response.id, signer_locator, message, signing_key)
            .await
    }

    async fn submit_approval(
        &self,
        transaction_id: &str,
        signer_locator: &str,
        message: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<TransactionResponse, SignerError> {
        use ed25519_dalek::Signer;

        let message_bytes = bs58::decode(message).into_vec().map_err(|e| {
            SignerError::SigningFailed(format!("Failed to decode approval message as base58: {e}"))
        })?;

        let signature = signing_key.sign(&message_bytes);
        let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

        let url = self.build_wallets_api_url(&["transactions", transaction_id, "approvals"])?;

        let body = serde_json::json!({
            "approvals": [{
                "signer": signer_locator,
                "signature": signature_b58
            }]
        });

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-API-KEY", &self.api_key)
            .json(&body)
            .send()
            .await?;

        Self::parse_response_with_required_field(response, "id", "submit_approval").await
    }

    fn derive_signing_key(
        secret: &str,
        api_key: &str,
    ) -> Result<ed25519_dalek::SigningKey, SignerError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let (project_id, environment) = Self::parse_api_key(api_key)?;

        let raw_secret = secret.strip_prefix("xmsk1_").unwrap_or(secret);
        if raw_secret.len() != 64 {
            return Err(SignerError::ConfigError(format!(
                "signer_secret must be a 64-char hex string (got {})",
                raw_secret.len()
            )));
        }
        let ikm = (0..raw_secret.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&raw_secret[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| {
                SignerError::ConfigError(format!("signer_secret is not valid hex: {e}"))
            })?;

        let info = format!("{project_id}:{environment}:solana-ed25519");
        let hkdf = Hkdf::<Sha256>::new(Some(b"crossmint"), &ikm);
        let mut key_bytes = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut key_bytes)
            .map_err(|e| SignerError::ConfigError(format!("HKDF expand failed: {e}")))?;

        Ok(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
    }

    fn parse_api_key(api_key: &str) -> Result<(String, String), SignerError> {
        // Format: {ck|sk}_{environment}_{base58data}
        // base58-decoded data is UTF-8: "projectId:nacl_signature"
        let mut parts = api_key.splitn(3, '_');
        parts.next(); // skip ck/sk prefix
        let environment = parts
            .next()
            .ok_or_else(|| SignerError::ConfigError("Invalid API key format".to_string()))?
            .to_string();
        let base58_data = parts
            .next()
            .ok_or_else(|| SignerError::ConfigError("Invalid API key format".to_string()))?;

        let decoded = bs58::decode(base58_data)
            .into_vec()
            .map_err(|e| SignerError::ConfigError(format!("Failed to decode API key data: {e}")))?;
        let decoded_str = std::str::from_utf8(&decoded).map_err(|e| {
            SignerError::ConfigError(format!("API key data is not valid UTF-8: {e}"))
        })?;
        let project_id = decoded_str
            .split(':')
            .next()
            .ok_or_else(|| {
                SignerError::ConfigError("Could not extract projectId from API key".to_string())
            })?
            .to_string();

        Ok((project_id, environment))
    }

    fn decode_base58_signature(signature_str: &str) -> Option<Signature> {
        let bytes = bs58::decode(signature_str).into_vec().ok()?;
        let sig_bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Signature::from(sig_bytes))
    }

    fn verify_signature_matches_message(
        &self,
        signature: &Signature,
        message: &[u8],
    ) -> Result<(), SignerError> {
        if signature.verify(&self.public_key.to_bytes(), message) {
            Ok(())
        } else {
            Err(SignerError::SigningFailed(
                "Crossmint returned a signature for different bytes".to_string(),
            ))
        }
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

        let transaction: VersionedTransaction = bincode::deserialize(&bytes).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to deserialize Crossmint onChain.transaction: {e}"
            ))
        })?;

        let required_signers = usize::from(transaction.message.header().num_required_signatures);
        let signer_keys = transaction.message.static_account_keys();
        if signer_keys.len() < required_signers {
            return Err(SignerError::SigningFailed(
                "Invalid account index: not enough account keys".to_string(),
            ));
        }

        if Self::debug_signatures_enabled() {
            let signer_keys_debug: Vec<String> = signer_keys
                .iter()
                .take(required_signers)
                .map(|pk| pk.to_string())
                .collect();
            eprintln!(
                "[crossmint-debug] decoded serialized transaction: expected_signer={}, required_signers={:?}, remote_message_len={}",
                self.public_key,
                signer_keys_debug,
                transaction.message.serialize().len()
            );
        }

        let position = signer_keys
            .iter()
            .take(required_signers)
            .position(|key| key == &self.public_key)
            .ok_or_else(|| {
                if Self::debug_signatures_enabled() {
                    eprintln!(
                        "[crossmint-debug] signer position lookup failed for expected_signer={}",
                        self.public_key
                    );
                }
                SignerError::SigningFailed(
                    "Failed to locate signer pubkey in Crossmint transaction".to_string(),
                )
            })?;

        let signature = transaction
            .signatures
            .get(position)
            .copied()
            .filter(|sig| *sig != Signature::default())
            .ok_or_else(|| {
                if Self::debug_signatures_enabled() {
                    eprintln!(
                        "[crossmint-debug] signature slot missing or default at position={} for expected_signer={}",
                        position, self.public_key
                    );
                }
                SignerError::SigningFailed(
                    "Crossmint onChain.transaction did not contain a signer signature".to_string(),
                )
            })?;

        let remote_message = transaction.message.serialize();
        self.verify_signature_matches_message(&signature, &remote_message)?;
        Ok(signature)
    }

    fn extract_signature_from_response(
        &self,
        response: &TransactionResponse,
        expected_message: &[u8],
    ) -> Result<Signature, SignerError> {
        if let Some(on_chain) = &response.on_chain {
            if let Some(serialized_transaction) = &on_chain.transaction {
                // Try to extract from the serialized transaction first. If that
                // fails, only accept txId if it verifies against the original
                // requested message bytes.
                match self.extract_signature_from_serialized_transaction(serialized_transaction) {
                    Ok(signature) => return Ok(signature),
                    Err(error) => {
                        if Self::debug_signatures_enabled() {
                            eprintln!(
                                "[crossmint-debug] serialized transaction extraction failed: {error:?}"
                            );
                        }
                    }
                }
            }

            if let Some(tx_id) = &on_chain.tx_id {
                if Self::debug_signatures_enabled() {
                    eprintln!(
                        "[crossmint-debug] validating txId fallback: expected_signer={}, tx_id_len={}, expected_message_len={}",
                        self.public_key,
                        tx_id.len(),
                        expected_message.len()
                    );
                }
                let signature = Self::decode_base58_signature(tx_id).ok_or_else(|| {
                    SignerError::SigningFailed(
                        "Crossmint onChain.txId was not a valid Solana signature".to_string(),
                    )
                })?;
                self.verify_signature_matches_message(&signature, expected_message)?;
                return Ok(signature);
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

        let expected_message = transaction.message_data();
        let serialized = bincode::serialize(transaction).map_err(|e| {
            SignerError::SerializationError(format!("Failed to serialize transaction: {e}"))
        })?;
        let transaction_b58 = bs58::encode(serialized).into_string();

        let create_response = self.create_transaction(transaction_b58).await?;
        let final_response = self.poll_transaction(create_response).await?;
        let signature = self.extract_signature_from_response(&final_response, &expected_message)?;

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
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::SigningFailed(
            "Crossmint sign_message is not supported for Solana wallets in this signer".to_string(),
        ))
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, keypair_sign_message, Keypair};
    use crate::test_util::{create_test_transaction, create_test_transaction_with_recipient};
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

    /// Helper to create a signer for tests that point to local wiremock HTTP URLs.
    /// Production URL validation stays enforced in `CrossmintSigner::new`.
    fn create_test_signer(
        base_url: &str,
        poll_interval_ms: u64,
        max_poll_attempts: u32,
    ) -> CrossmintSigner {
        CrossmintSigner {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer: None,
            api_base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(CLIENT_TIMEOUT)
                .build()
                .unwrap(),
            public_key: Pubkey::default(),
            poll_interval_ms,
            max_poll_attempts,
            signing_key: None,
        }
    }

    fn create_url_builder_test_signer(wallet_locator: &str) -> CrossmintSigner {
        let mut signer = create_test_signer(
            "https://example.com/api",
            DEFAULT_POLL_INTERVAL_MS,
            DEFAULT_MAX_POLL_ATTEMPTS,
        );
        signer.wallet_locator = wallet_locator.to_string();
        signer
    }

    fn build_url_and_path(wallet_locator: &str, segments: &[&str]) -> (String, String) {
        let signer = create_url_builder_test_signer(wallet_locator);
        let built_url = signer.build_wallets_api_url(segments).unwrap();
        let path = reqwest::Url::parse(&built_url).unwrap().path().to_string();
        (built_url, path)
    }

    #[test]
    fn test_build_wallets_api_url_encodes_raw_slashes_in_wallet_locator() {
        let (built_url, path) = build_url_and_path("userId:test-user/child:solana:smart", &[]);

        assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Atest-user%2Fchild%3Asolana%3Asmart"
        );
        assert_eq!(
            path,
            "/api/2025-06-09/wallets/userId%3Atest-user%2Fchild%3Asolana%3Asmart"
        );
        assert!(
            !path.contains("/child"),
            "wallet locator slash must stay inside a single encoded path segment: {path}"
        );
    }

    #[test]
    fn test_build_wallets_api_url_prevents_dot_segment_retargeting() {
        let (built_url, path) =
            build_url_and_path("userId:attacker/../victim:solana:smart", &["transactions"]);

        assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Aattacker%2F..%2Fvictim%3Asolana%3Asmart/transactions"
        );
        assert_eq!(
            path,
            "/api/2025-06-09/wallets/userId%3Aattacker%2F..%2Fvictim%3Asolana%3Asmart/transactions"
        );
        assert_ne!(
            path, "/api/2025-06-09/wallets/victim%3Asolana%3Asmart/transactions",
            "wallet locator must not normalize into a different wallet path"
        );
    }

    #[test]
    fn test_build_wallets_api_url_double_encodes_encoded_traversal_sequences() {
        for (wallet_locator, expected_fragment) in [
            (
                "userId:attacker%2Fvictim:solana:smart",
                "userId%3Aattacker%252Fvictim%3Asolana%3Asmart",
            ),
            (
                "userId:attacker%2e%2e%2Fvictim:solana:smart",
                "userId%3Aattacker%252e%252e%252Fvictim%3Asolana%3Asmart",
            ),
        ] {
            let (built_url, path) = build_url_and_path(wallet_locator, &[]);

            assert!(
                built_url.contains(expected_fragment),
                "expected encoded traversal fragment {expected_fragment} in URL {built_url}"
            );
            assert!(
                path.contains(expected_fragment),
                "expected encoded traversal fragment {expected_fragment} in path {path}"
            );
        }
    }

    #[test]
    fn test_build_wallets_api_url_encodes_query_and_fragment_metacharacters() {
        let (built_url, path) = build_url_and_path("userId:test?wallet#fragment:solana:smart", &[]);

        assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Atest%3Fwallet%23fragment%3Asolana%3Asmart"
        );
        assert_eq!(
            path,
            "/api/2025-06-09/wallets/userId%3Atest%3Fwallet%23fragment%3Asolana%3Asmart"
        );
    }

    #[test]
    fn test_build_wallets_api_url_matches_typescript_encodeuricomponent_behavior() {
        let (built_url, path) = build_url_and_path(
            "userId:alice/../wallet?draft#frag:solana:smart",
            &["transactions", "tx-123", "approvals"],
        );

        assert_eq!(
            built_url,
            "https://example.com/api/2025-06-09/wallets/userId%3Aalice%2F..%2Fwallet%3Fdraft%23frag%3Asolana%3Asmart/transactions/tx-123/approvals"
        );
        assert_eq!(
            path,
            "/api/2025-06-09/wallets/userId%3Aalice%2F..%2Fwallet%3Fdraft%23frag%3Asolana%3Asmart/transactions/tx-123/approvals"
        );
    }

    #[test]
    fn test_new_rejects_insecure_api_base_url() {
        let result = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer_secret: None,
            signer: None,
            api_base_url: Some("http://insecure.example.com".to_string()),
            poll_interval_ms: None,
            max_poll_attempts: None,
        });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
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

        let mut signer = create_test_signer(
            &server.uri(),
            DEFAULT_POLL_INTERVAL_MS,
            DEFAULT_MAX_POLL_ATTEMPTS,
        );

        signer.init().await.unwrap();
        assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
    }

    #[test]
    fn test_parse_test_signer_pubkey_override_accepts_valid_pubkey() {
        let keypair = Keypair::new();
        let pubkey = keypair_pubkey(&keypair);
        let pubkey_str = pubkey.to_string();

        let parsed =
            CrossmintSigner::parse_test_signer_pubkey_override(Some(pubkey_str.as_str())).unwrap();
        assert_eq!(parsed, Some(pubkey));
    }

    #[test]
    fn test_parse_test_signer_pubkey_override_rejects_invalid_pubkey() {
        let result = CrossmintSigner::parse_test_signer_pubkey_override(Some("not-a-pubkey"));
        assert!(matches!(result, Err(SignerError::ConfigError(_))));
    }

    #[tokio::test]
    async fn test_init_url_encodes_wallet_locator() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let address = keypair_pubkey(&keypair).to_string();
        let locator = "userId:test-user:solana:smart";

        Mock::given(method("GET"))
            .and(path(
                "/2025-06-09/wallets/userId%3Atest-user%3Asolana%3Asmart",
            ))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&address))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(
            &server.uri(),
            DEFAULT_POLL_INTERVAL_MS,
            DEFAULT_MAX_POLL_ATTEMPTS,
        );
        signer.wallet_locator = locator.to_string();

        signer.init().await.unwrap();
        assert_eq!(signer.pubkey(), keypair_pubkey(&keypair));
    }

    #[tokio::test]
    async fn test_sign_message_not_supported() {
        let signer = CrossmintSigner::new(CrossmintSignerConfig {
            api_key: "test-api-key".to_string(),
            wallet_locator: "test-wallet".to_string(),
            signer_secret: None,
            signer: None,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
        })
        .unwrap();

        let result = signer.sign_message(b"hello").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SigningFailed(msg) => {
                assert!(
                    msg.contains("not supported"),
                    "Unexpected error message: {msg}"
                );
            }
            other => panic!("Expected SigningFailed error, got: {:?}", other),
        }
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

        let mut signer = create_test_signer(&server.uri(), 1, 2);
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&signer_pubkey);
        let mut signed_remote_tx = local_tx.clone();
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

        let (_serialized, signature) = signer
            .sign_transaction(&mut local_tx)
            .await
            .unwrap()
            .into_signed_transaction();

        assert_eq!(signature, expected_signature);
        assert!(!_serialized.is_empty());
    }

    #[tokio::test]
    async fn test_sign_transaction_rejects_approval_signatures_for_local_transaction_bytes() {
        let server = MockServer::start().await;
        let wallet_keypair = Keypair::new();
        let signer_address = keypair_pubkey(&wallet_keypair).to_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_address))
            .mount(&server)
            .await;

        let approval_signer = Keypair::new();
        let approval_signature =
            keypair_sign_message(&approval_signer, b"crossmint-approval-payload");
        let approval_signature_b58 = bs58::encode(approval_signature.as_ref()).into_string();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-approval",
                "status": "success",
                "approvals": {
                    "submitted": [
                        { "signature": approval_signature_b58 }
                    ]
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 1);
        signer.init().await.unwrap();

        let mut tx = create_test_transaction(&signer.pubkey());
        let result = signer.sign_transaction(&mut tx).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SigningFailed(msg) => {
                assert!(
                    msg.contains("Unable to extract signature"),
                    "Unexpected error message: {msg}"
                );
            }
            other => panic!("Expected SigningFailed error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_sign_transaction_accepts_signature_from_on_chain_transaction_bytes() {
        let server = MockServer::start().await;
        let wallet_keypair = Keypair::new();
        let signer_pubkey = keypair_pubkey(&wallet_keypair);
        let signer_address = signer_pubkey.to_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_address))
            .mount(&server)
            .await;

        let recipient = Pubkey::new_unique();
        let mut remote_tx = create_test_transaction_with_recipient(&signer_pubkey, &recipient);
        let remote_signature = keypair_sign_message(&wallet_keypair, &remote_tx.message_data());
        TransactionUtil::add_signature_to_transaction(
            &mut remote_tx,
            &signer_pubkey,
            remote_signature,
        )
        .unwrap();
        let remote_on_chain_transaction =
            bs58::encode(bincode::serialize(&remote_tx).unwrap()).into_string();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-mismatch",
                "status": "success",
                "onChain": {
                    "transaction": remote_on_chain_transaction
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 1);
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&signer_pubkey);
        let (_serialized, signature) = signer
            .sign_transaction(&mut local_tx)
            .await
            .unwrap()
            .into_signed_transaction();
        assert_eq!(signature, remote_signature);
    }

    #[tokio::test]
    async fn test_sign_transaction_prefers_on_chain_transaction_signature_over_txid_fallback() {
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

        // onChain.transaction with different message bytes (different recipient)
        let recipient = Pubkey::new_unique();
        let mut remote_tx = create_test_transaction_with_recipient(&signer_pubkey, &recipient);
        let remote_sig = keypair_sign_message(&keypair, &remote_tx.message_data());
        TransactionUtil::add_signature_to_transaction(&mut remote_tx, &signer_pubkey, remote_sig)
            .unwrap();
        let remote_on_chain_transaction =
            bs58::encode(bincode::serialize(&remote_tx).unwrap()).into_string();

        // onChain.txId is only valid for the remote transaction bytes, not the local ones.
        let tx_id = bs58::encode(remote_sig.as_ref()).into_string();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-fallthrough",
                "status": "success",
                "onChain": {
                    "transaction": remote_on_chain_transaction,
                    "txId": tx_id
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 1);
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&signer_pubkey);
        let (_serialized, signature) = signer
            .sign_transaction(&mut local_tx)
            .await
            .unwrap()
            .into_signed_transaction();
        assert_eq!(signature, remote_sig);
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

        let mut signer = create_test_signer(&server.uri(), 1, 2);
        signer.init().await.unwrap();

        let mut tx = create_test_transaction(&signer.pubkey());
        let result = signer.sign_transaction(&mut tx).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SigningFailed(msg) => {
                assert!(
                    msg.contains("awaiting approval"),
                    "Unexpected error message: {msg}"
                );
            }
            other => panic!("Expected SigningFailed error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_sign_transaction_success_on_last_polled_response() {
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

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "pending",
                "chainType": "solana",
                "walletType": "smart"
            })))
            .mount(&server)
            .await;

        let mut tx = create_test_transaction(&signer_pubkey);
        let expected_signature = keypair_sign_message(&keypair, &tx.message_data());
        let tx_id = bs58::encode(expected_signature.as_ref()).into_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions/tx-123"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "success",
                "chainType": "solana",
                "walletType": "smart",
                "onChain": {
                    "txId": tx_id
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 1);
        signer.init().await.unwrap();

        let (_serialized, signature) = signer
            .sign_transaction(&mut tx)
            .await
            .unwrap()
            .into_signed_transaction();
        assert_eq!(signature, expected_signature);
    }
}
