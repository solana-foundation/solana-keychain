//! Crossmint API signer integration

mod types;

use crate::sdk_adapter::{Pubkey, Signature, Transaction, VersionedTransaction};
use crate::traits::SignTransactionResult;
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
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
    /// choice of what gets approved. The signer confirms after the fact that its
    /// approval covers the transaction that executed, not that the transaction
    /// matches the caller's intent.
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
    /// Every delegated-signer key the configuration makes known. Smart wallets sign
    /// with one of these rather than with `public_key`.
    delegated_pubkeys: Vec<Pubkey>,
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

        let delegated_pubkeys =
            Self::resolve_delegated_pubkeys(signing_key.as_ref(), signer.as_deref());

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
            delegated_pubkeys,
        })
    }

    /// Every delegated-signer key the configuration makes known.
    ///
    /// A smart wallet signs through its delegated signer, not the wallet address.
    /// Both sources are collected because a `signer` locator may name a different
    /// key than `signer_secret` derives, and either can be the one that signs.
    fn resolve_delegated_pubkeys(
        signing_key: Option<&ed25519_dalek::SigningKey>,
        signer_locator: Option<&str>,
    ) -> Vec<Pubkey> {
        let mut candidates = Vec::new();
        if let Some(key) = signing_key {
            candidates.push(Pubkey::from(key.verifying_key().to_bytes()));
        }
        if let Some(encoded) = signer_locator.and_then(|l| l.strip_prefix("server:")) {
            if let Ok(pubkey) = Pubkey::from_str(encoded.trim()) {
                candidates.push(pubkey);
            }
        }
        candidates
    }

    /// Keys that may have signed: the wallet address for `mpc`, the delegated signer
    /// for `smart`. The response does not say which, so try both.
    fn verification_candidates(&self) -> Vec<Pubkey> {
        let mut candidates = vec![self.public_key];
        for delegated in &self.delegated_pubkeys {
            if !candidates.contains(delegated) {
                candidates.push(*delegated);
            }
        }
        candidates
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
        let mut approval_submitted = false;
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

    fn decode_base58_signature(signature_str: &str) -> Option<Signature> {
        let bytes = bs58::decode(signature_str).into_vec().ok()?;
        let sig_bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Signature::from(sig_bytes))
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

        // Verify against the bytes Crossmint signed, which differ from the caller's
        // once it rewrites to sponsor gas. Require a verifying signature, not just
        // presence in a slot: the wallet address can occupy a slot it never signed.
        let remote_message = transaction.message.serialize();
        let found = self
            .verification_candidates()
            .into_iter()
            .find_map(|candidate| {
                signer_keys
                    .iter()
                    .take(required_signers)
                    .position(|key| key == &candidate)
                    .and_then(|position| transaction.signatures.get(position).copied())
                    .filter(|signature| {
                        *signature != Signature::default()
                            && signature.verify(&candidate.to_bytes(), &remote_message)
                    })
            });

        match found {
            Some(signature) => Ok((signature, transaction)),
            None => Err(SignerError::SigningFailed(
                "No configured signer holds a verifying signature in the Crossmint transaction"
                    .to_string(),
            )),
        }
    }

    /// This wallet's signature over the transaction Crossmint executed.
    ///
    /// For a rewritten transaction it arrives in `approvals.submitted` covering the
    /// rewritten message, not in a signature slot. Verified locally regardless.
    fn signature_from_approvals(
        &self,
        response: &TransactionResponse,
        serialized_transaction: &str,
    ) -> Option<(Signature, VersionedTransaction)> {
        let submitted = &response.approvals.as_ref()?.submitted;
        if submitted.is_empty() {
            return None;
        }
        let bytes = bs58::decode(serialized_transaction).into_vec().ok()?;
        let transaction: VersionedTransaction = bincode::deserialize(&bytes).ok()?;
        let executed_message = transaction.message.serialize();
        let candidates = self.verification_candidates();
        for entry in submitted {
            let address = entry.signer.as_ref()?.address.as_deref()?;
            let encoded = entry.signature.as_deref()?;
            let Ok(approver) = Pubkey::from_str(address) else {
                continue;
            };
            let Some(signature) = Self::decode_base58_signature(encoded) else {
                continue;
            };
            if candidates.contains(&approver)
                && signature.verify(&approver.to_bytes(), &executed_message)
            {
                return Some((signature, transaction));
            }
        }
        None
    }

    /// The signing result, plus the broadcast transaction when Crossmint rewrote one.
    ///
    /// `Some` means the signature covers Crossmint's bytes, not the caller's.
    fn extract_signature_from_response(
        &self,
        response: &TransactionResponse,
        expected_message: &[u8],
    ) -> Result<(Signature, Option<VersionedTransaction>), SignerError> {
        let mut embedded_error: Option<SignerError> = None;
        if let Some(on_chain) = &response.on_chain {
            if let Some(serialized_transaction) = &on_chain.transaction {
                // Try to extract from the serialized transaction first. If that
                // fails, only accept txId if it verifies against the original
                // requested message bytes.
                match self.extract_signature_from_serialized_transaction(serialized_transaction) {
                    Ok((signature, returned)) => {
                        let rewritten = returned.message.serialize() != expected_message;
                        return Ok((signature, rewritten.then_some(returned)));
                    }
                    Err(error) => {
                        // A rewritten transaction's signature is in approvals.submitted.
                        if let Some(found) =
                            self.signature_from_approvals(response, serialized_transaction)
                        {
                            return Ok((found.0, Some(found.1)));
                        }
                        if on_chain.tx_id.is_none() {
                            return Err(error);
                        }
                        // Keep this error as the cause: it names the check that
                        // failed, where the txId path only reports a mismatch.
                        embedded_error = Some(error);
                    }
                }
            }

            if let Some(tx_id) = &on_chain.tx_id {
                let signature = Self::decode_base58_signature(tx_id).ok_or_else(|| {
                    SignerError::SigningFailed(
                        "Crossmint onChain.txId was not a valid Solana signature".to_string(),
                    )
                })?;
                // A txId counts only if it covers the caller's bytes, and any
                // configured signer may have produced it.
                let verified = self
                    .verification_candidates()
                    .iter()
                    .any(|candidate| signature.verify(&candidate.to_bytes(), expected_message));
                if !verified {
                    return Err(embedded_error.unwrap_or_else(|| {
                        SignerError::SigningFailed(
                            "Crossmint returned a signature for different bytes".to_string(),
                        )
                    }));
                }
                return Ok((signature, None));
            }
        }

        Err(SignerError::SigningFailed(
            "Unable to extract signature from Crossmint transaction response".to_string(),
        ))
    }

    /// Sign `transaction` through Crossmint's managed wallet flow.
    ///
    /// Crossmint may rewrite the transaction to sponsor gas and broadcast it itself.
    /// When it does, `transaction` is left unmodified and the returned serialized
    /// transaction is empty, because the signature covers Crossmint's bytes. The
    /// signature is placed in `transaction` only when Crossmint signed it as given.
    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignTransactionResult, SignerError> {
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
        let (signature, broadcast) =
            self.extract_signature_from_response(&final_response, &expected_message)?;

        if broadcast.is_some() {
            // Already landed, so complete regardless of the slots the returned copy
            // shows filled, and nothing is left for the caller to send.
            return Ok(SignTransactionResult::Complete((String::new(), signature)));
        }

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok(TransactionUtil::classify_signed_transaction(
            transaction,
            (
                TransactionUtil::serialize_transaction(transaction)?,
                signature,
            ),
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
        self.sign_and_serialize(tx).await
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
            delegated_pubkeys: Vec::new(),
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

    /// A smart wallet is signed by its delegated signer, not by the wallet address
    /// the API reports, so the delegated key must be a verification candidate.
    #[tokio::test]
    async fn test_sign_transaction_locates_delegated_signer_signature() {
        let server = MockServer::start().await;
        let wallet_keypair = Keypair::new();
        let wallet_pubkey = keypair_pubkey(&wallet_keypair);
        let delegated_keypair = Keypair::new();
        let delegated_pubkey = keypair_pubkey(&delegated_keypair);

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .respond_with(wallet_response(&wallet_pubkey.to_string()))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 2);
        signer.delegated_pubkeys = vec![delegated_pubkey];
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&wallet_pubkey);
        let mut rewritten_tx = create_test_transaction(&delegated_pubkey);
        let expected_signature =
            keypair_sign_message(&delegated_keypair, &rewritten_tx.message_data());
        TransactionUtil::add_signature_to_transaction(
            &mut rewritten_tx,
            &delegated_pubkey,
            expected_signature,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-delegated",
                "status": "success",
                "onChain": {
                    "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                        .into_string()
                }
            })))
            .mount(&server)
            .await;

        let (serialized, signature) = signer
            .sign_transaction(&mut local_tx)
            .await
            .unwrap()
            .into_signed_transaction();

        assert_eq!(signature, expected_signature);
        assert!(serialized.is_empty());
        // The wallet address remains the signer's public identity.
        assert_eq!(signer.pubkey(), wallet_pubkey);
    }

    /// A wallet can be configured with both `signer_secret` and an explicit `signer`
    /// locator naming a different key, e.g. the wallet's admin signer. Either may be
    /// the key that actually signs, so both must be candidates.
    #[test]
    fn test_resolve_delegated_pubkeys_collects_both_sources() {
        let admin = keypair_pubkey(&Keypair::new());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let derived = Pubkey::from(signing_key.verifying_key().to_bytes());

        let candidates = CrossmintSigner::resolve_delegated_pubkeys(
            Some(&signing_key),
            Some(&format!("server:{admin}")),
        );

        assert!(
            candidates.contains(&derived) && candidates.contains(&admin),
            "both the derived server signer and the locator's admin signer must be candidates, got {candidates:?}"
        );
    }

    /// Widening the candidate set must not accept a key that is neither the wallet
    /// address nor the configured delegated signer.
    #[tokio::test]
    async fn test_sign_transaction_rejects_unrelated_signer_key() {
        let server = MockServer::start().await;
        let wallet_keypair = Keypair::new();
        let wallet_pubkey = keypair_pubkey(&wallet_keypair);
        let stranger = Keypair::new();
        let stranger_pubkey = keypair_pubkey(&stranger);

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .respond_with(wallet_response(&wallet_pubkey.to_string()))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 2);
        signer.delegated_pubkeys = vec![keypair_pubkey(&Keypair::new())];
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&wallet_pubkey);
        let mut rewritten_tx = create_test_transaction(&stranger_pubkey);
        let signature = keypair_sign_message(&stranger, &rewritten_tx.message_data());
        TransactionUtil::add_signature_to_transaction(
            &mut rewritten_tx,
            &stranger_pubkey,
            signature,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-stranger",
                "status": "success",
                "onChain": {
                    "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                        .into_string()
                }
            })))
            .mount(&server)
            .await;

        let result = signer.sign_transaction(&mut local_tx).await;
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    /// Crossmint sponsors gas, so it is the fee payer and the message it signs
    /// differs from the caller's. Its signature must never be placed in the
    /// caller's transaction, which could not verify with it.
    #[tokio::test]
    async fn test_sign_transaction_rewritten_is_reported_as_a_broadcast_result() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer_pubkey = keypair_pubkey(&keypair);

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_pubkey.to_string()))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 2);
        signer.init().await.unwrap();

        let mut local_tx = create_test_transaction(&signer_pubkey);
        let mut rewritten_tx = create_test_transaction(&signer_pubkey);
        assert_ne!(rewritten_tx.message_data(), local_tx.message_data());
        let expected_signature = keypair_sign_message(&keypair, &rewritten_tx.message_data());
        TransactionUtil::add_signature_to_transaction(
            &mut rewritten_tx,
            &signer_pubkey,
            expected_signature,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "success",
                "chainType": "solana",
                "walletType": "smart",
                "onChain": {
                    "transaction": bs58::encode(bincode::serialize(&rewritten_tx).unwrap())
                        .into_string()
                }
            })))
            .mount(&server)
            .await;

        let result = signer.sign_transaction(&mut local_tx).await.unwrap();
        assert!(matches!(result, SignTransactionResult::Complete(_)));
        let (serialized, signature) = result.into_signed_transaction();

        assert_eq!(signature, expected_signature);
        assert!(
            serialized.is_empty(),
            "a Crossmint-broadcast transaction leaves nothing for the caller to send"
        );
        assert!(
            local_tx
                .signatures
                .iter()
                .all(|s| *s == Signature::default()),
            "the caller's transaction must not carry a signature over other bytes"
        );
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

    fn attach_approval_signer(
        signer: &mut CrossmintSigner,
        locator: &str,
    ) -> ed25519_dalek::SigningKey {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        signer.signing_key = Some(key.clone());
        signer.signer = Some(locator.to_string());
        key
    }

    #[tokio::test]
    async fn test_sign_transaction_submits_approval_once_and_polls_after_async_registration() {
        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer_pubkey = keypair_pubkey(&keypair);
        let locator = "server:test-approver";
        let approval_message = bs58::encode(b"approval-challenge").into_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_pubkey.to_string()))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "awaiting-approval",
                "approvals": {
                    "pending": [
                        { "signer": { "locator": locator }, "message": approval_message }
                    ]
                }
            })))
            .mount(&server)
            .await;

        // Approval is acknowledged but Crossmint has not registered it yet:
        // the transaction still reports awaiting-approval with nothing pending.
        Mock::given(method("POST"))
            .and(path(
                "/2025-06-09/wallets/test-wallet/transactions/tx-123/approvals",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "awaiting-approval",
                "approvals": { "pending": [] }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 5);
        attach_approval_signer(&mut signer, locator);
        signer.init().await.unwrap();

        let mut tx = create_test_transaction(&signer_pubkey);
        let expected_signature = keypair_sign_message(&keypair, &tx.message_data());
        let tx_id = bs58::encode(expected_signature.as_ref()).into_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions/tx-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123",
                "status": "success",
                "onChain": { "txId": tx_id }
            })))
            .mount(&server)
            .await;

        let (_serialized, signature) = signer
            .sign_transaction(&mut tx)
            .await
            .unwrap()
            .into_signed_transaction();
        assert_eq!(signature, expected_signature);
    }

    #[tokio::test]
    async fn test_sign_transaction_selects_pending_approval_matching_signer_locator() {
        use ed25519_dalek::Signer as _;
        use wiremock::matchers::body_string_contains;

        let server = MockServer::start().await;
        let keypair = Keypair::new();
        let signer_pubkey = keypair_pubkey(&keypair);
        let locator = "server:test-approver";

        let our_message_bytes = b"our-approval-challenge";
        let our_message = bs58::encode(our_message_bytes).into_string();
        let other_message = bs58::encode(b"someone-elses-challenge").into_string();

        Mock::given(method("GET"))
            .and(path("/2025-06-09/wallets/test-wallet"))
            .and(header("x-api-key", "test-api-key"))
            .respond_with(wallet_response(&signer_pubkey.to_string()))
            .mount(&server)
            .await;

        // pending[0] belongs to another approver; ours is second.
        Mock::given(method("POST"))
            .and(path("/2025-06-09/wallets/test-wallet/transactions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "tx-multi",
                "status": "awaiting-approval",
                "approvals": {
                    "pending": [
                        { "signer": { "locator": "server:other-approver" }, "message": other_message },
                        { "signer": { "locator": locator }, "message": our_message }
                    ]
                }
            })))
            .mount(&server)
            .await;

        let mut signer = create_test_signer(&server.uri(), 1, 5);
        let signing_key = attach_approval_signer(&mut signer, locator);
        signer.init().await.unwrap();

        let mut tx = create_test_transaction(&signer_pubkey);
        let expected_tx_signature = keypair_sign_message(&keypair, &tx.message_data());
        let tx_id = bs58::encode(expected_tx_signature.as_ref()).into_string();

        // Only an approval whose signature covers OUR challenge bytes (and
        // carries our locator) is answered; signing pending[0] would miss this
        // mock and fail the test.
        let expected_approval_signature =
            bs58::encode(signing_key.sign(our_message_bytes).to_bytes()).into_string();
        Mock::given(method("POST"))
            .and(path(
                "/2025-06-09/wallets/test-wallet/transactions/tx-multi/approvals",
            ))
            .and(body_string_contains(&expected_approval_signature))
            .and(body_string_contains(locator))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-multi",
                "status": "success",
                "onChain": { "txId": tx_id }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (_serialized, signature) = signer
            .sign_transaction(&mut tx)
            .await
            .unwrap()
            .into_signed_transaction();
        assert_eq!(signature, expected_tx_signature);
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
