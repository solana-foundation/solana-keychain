//! Crossmint API signer integration

mod types;

use crate::remote_util::{read_body_capped, validate_https_url};
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::signature_from_base58;
use crate::traits::SignTransactionResult;
use crate::transaction_util::{
    deserialize_wire_transaction, idempotency_key_from_message, serialize_wire_transaction,
    unconfirmed_unless_rejected,
};
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use std::fmt::Write;
use std::str::FromStr;
use types::{
    CreateTransactionParams, CreateTransactionRequest, TransactionResponse, WalletResponse,
};

const DEFAULT_BASE_URL: &str = "https://www.crossmint.com/api";
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 60;

/// Configuration for creating a CrossmintSigner
#[derive(Clone)]
pub struct CrossmintSignerConfig {
    pub api_key: String,
    pub wallet_locator: String,
    /// Optional server signer secret (`xmsk1_<64hex>`). When provided, the signer
    /// derives an Ed25519 keypair via HKDF and automatically signs any
    /// `awaiting-approval` transactions from the Crossmint API.
    ///
    /// Trust boundary: the approval challenge is the message of the transaction
    /// Crossmint will execute, which is not derivable from the one submitted because
    /// Crossmint rewrites it to sponsor gas. Setting this delegates to Crossmint the
    /// choice of what gets approved. The provider is trusted to execute the
    /// approved transaction, which may not match the caller's submitted bytes.
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
    public_key: Option<Pubkey>,
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

        validate_https_url(&api_base_url)?;

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

        let client = HttpClientConfig {
            request_timeout: Some(CLIENT_TIMEOUT),
            connect_timeout: None,
        }
        .build_client()?;

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
            public_key: None,
            poll_interval_ms,
            max_poll_attempts,
            signing_key,
        })
    }

    fn initialized_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.public_key.ok_or_else(|| {
            SignerError::ConfigError(
                "CrossmintSigner is not initialized; call init() before signing".to_string(),
            )
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

        self.public_key = Some(Pubkey::from_str(&wallet.address).map_err(|_| {
            SignerError::InvalidPublicKey(
                "Invalid Solana public key returned by Crossmint wallet".to_string(),
            )
        })?);

        Ok(())
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
        idempotency_key: &str,
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
            .header("x-idempotency-key", idempotency_key)
            .json(&request)
            .send()
            .await
            .map_err(|error| unconfirmed_unless_rejected(None, error.into()))?;

        let status = response.status().as_u16();
        Self::parse_response_with_required_field(response, "id", "create_transaction")
            .await
            .map_err(|error| unconfirmed_unless_rejected(Some(status), error))
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
                let _ = write!(encoded, "%{byte:02X}");
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
        let body = read_body_capped(response).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);

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

    fn transaction_failure(response: &TransactionResponse) -> SignerError {
        let detail = response
            .error
            .as_ref()
            .map(serde_json::Value::to_string)
            .unwrap_or_else(|| "unknown error".to_string());
        SignerError::SigningFailed(format!("Crossmint transaction failed: {detail}"))
    }

    async fn poll_transaction(
        &self,
        mut response: TransactionResponse,
    ) -> Result<TransactionResponse, SignerError> {
        let mut approval_submitted = false;
        for _ in 0..self.max_poll_attempts {
            match response.status.as_str() {
                "success" => return Ok(response),
                "failed" => {
                    return Err(Self::transaction_failure(&response));
                }
                // Submit our approval at most once; Crossmint may register it
                // asynchronously, so afterwards awaiting-approval is treated
                // like any other in-flight status and re-polled.
                "awaiting-approval" if !approval_submitted => {
                    response = self.handle_awaiting_approval(response).await?;
                    approval_submitted = true;
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
            "failed" => Err(Self::transaction_failure(&response)),
            "awaiting-approval" if !approval_submitted => Err(SignerError::SigningFailed(
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

        // On a multi-approver wallet `pending` may contain challenges for other
        // approvers; signing one of those with our key yields a vendor 4xx, so
        // only the entry matching our signer locator is ours to approve.
        let pending = response
            .approvals
            .as_ref()
            .and_then(|a| {
                a.pending.iter().find(|p| {
                    p.signer.as_ref().and_then(|s| s.locator.as_deref())
                        == Some(signer_locator.as_str())
                })
            })
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint transaction is awaiting approval; additional signer approvals are required".to_string(),
                )
            })?;

        let message = pending.message.as_deref().ok_or_else(|| {
            SignerError::SigningFailed(
                "Crossmint transaction awaiting approval but no pending message found".to_string(),
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

    /// The landed transaction's fee-payer (slot 0) signature, the value RPC
    /// transaction lookups accept.
    fn broadcast_transaction_id(
        transaction: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        transaction
            .message
            .static_account_keys()
            .first()
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint transaction has no fee payer to identify it by".to_string(),
                )
            })?;
        let signature = transaction
            .signatures
            .first()
            .copied()
            .filter(|signature| *signature != Signature::default())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint transaction carries no fee-payer signature to identify it by"
                        .to_string(),
                )
            })?;
        Ok(signature)
    }

    fn extract_signature_from_serialized_transaction(
        &self,
        serialized_transaction: &str,
    ) -> Result<(Signature, VersionedTransaction), SignerError> {
        let bytes = bs58::decode(serialized_transaction)
            .into_vec()
            .map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to decode Crossmint onChain.transaction as base58: {e}"
                ))
            })?;

        let transaction: VersionedTransaction =
            deserialize_wire_transaction(&bytes).map_err(|e| {
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

        let signature = transaction
            .signatures
            .first()
            .copied()
            .filter(|signature| *signature != Signature::default())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Crossmint transaction carries no signer signature".to_string(),
                )
            })?;
        Ok((signature, transaction))
    }

    /// The signature identifying the transaction Crossmint landed.
    ///
    /// When Crossmint landed different bytes than the caller's, this is the
    /// landed transaction's fee-payer identifier rather than a signature over
    /// the caller's message.
    fn extract_signature_from_response(
        &self,
        response: &TransactionResponse,
        expected_message: &[u8],
    ) -> Result<Signature, SignerError> {
        if let Some(on_chain) = &response.on_chain {
            if let Some(serialized_transaction) = &on_chain.transaction {
                match self.extract_signature_from_serialized_transaction(serialized_transaction) {
                    Ok((signature, returned)) => {
                        if returned.message.serialize() == expected_message {
                            return Ok(signature);
                        }
                        return Self::broadcast_transaction_id(&returned);
                    }
                    Err(error) => {
                        if on_chain.tx_id.is_none() {
                            return Err(error);
                        }
                    }
                }
            }

            if let Some(tx_id) = &on_chain.tx_id {
                let signature = signature_from_base58(tx_id).map_err(|_| {
                    SignerError::SigningFailed(
                        "Crossmint onChain.txId was not a valid Solana signature".to_string(),
                    )
                })?;
                return Ok(signature);
            }
        }

        Err(SignerError::SigningFailed(
            "Unable to extract signature from Crossmint transaction response".to_string(),
        ))
    }

    /// Submit `transaction` through Crossmint's managed wallet flow and return the
    /// signature identifying the transaction Crossmint landed.
    ///
    /// Crossmint may rewrite the transaction to sponsor gas, so the returned
    /// signature does not necessarily cover the caller's bytes; it is the landed
    /// transaction's identifier, usable with RPC transaction lookups.
    /// `transaction` is never modified.
    ///
    /// Not retry-safe: any failure after the create is accepted returns
    /// [`SignerError::BroadcastUnconfirmed`] carrying the Crossmint transaction id;
    /// check that transaction with Crossmint before retrying. A create that fails
    /// without a usable response returns `BroadcastUnconfirmed` with no id.
    ///
    /// Each create carries an `x-idempotency-key` derived from the message bytes,
    /// so replaying these exact bytes cannot create a second transaction; a
    /// rebuilt transaction derives a different key and executes as a new
    /// transfer.
    async fn execute_managed_transaction(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        self.initialized_pubkey()?;

        let expected_message = transaction.message.serialize();
        let serialized = serialize_wire_transaction(transaction)?;
        let transaction_b58 = bs58::encode(serialized).into_string();
        let idempotency_key = idempotency_key_from_message(&expected_message);

        let create_response = self
            .create_transaction(transaction_b58, &idempotency_key)
            .await?;
        let provider_tx_id = create_response.id.clone();
        // Post-create failures leave an outcome Crossmint may still execute, so
        // they surface as BroadcastUnconfirmed with the transaction id.
        self.finish_managed_transaction(create_response, &expected_message)
            .await
            .map_err(|error| SignerError::BroadcastUnconfirmed {
                provider_tx_id: Some(provider_tx_id),
                provider_status: None,
                detail: error.detail_string(),
            })
    }

    async fn finish_managed_transaction(
        &self,
        create_response: TransactionResponse,
        expected_message: &[u8],
    ) -> Result<Signature, SignerError> {
        let final_response = self.poll_transaction(create_response).await?;
        self.extract_signature_from_response(&final_response, expected_message)
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
            .expect("CrossmintSigner is not initialized; call init() first")
    }

    fn broadcasts_transactions(&self) -> bool {
        true
    }

    async fn sign_transaction(
        &self,
        _tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        Err(SignerError::SigningFailed(
            "Crossmint executes every transaction server-side; call sign_and_send_transaction instead"
                .to_string(),
        ))
    }

    async fn sign_and_send_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        self.execute_managed_transaction(tx).await
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
mod tests;
