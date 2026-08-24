//! Fireblocks API signer integration

mod jwt;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::{
    error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner,
    transaction_util, transaction_util::TransactionUtil,
};
use std::{str::FromStr, sync::Arc};
use types::{
    CreateTransactionRequest, CreateTransactionResponse, ExtraParameters,
    ProgramCallExtraParameters, RawExtraParameters, RawMessage, RawMessageData,
    TransactionResponse, TransactionSource, VaultAddress, VaultAddressesResponse,
};

use crate::remote_util::{parse_json_response, poll_until, PollOutcome};
use crate::signature_util::{signature_from_base58, signature_from_hex, verify_or_reject};

const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 300;
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SigningMode {
    Raw,
    ProgramCall,
}

/// Fireblocks-based signer using Fireblocks' API
#[derive(Clone)]
pub struct FireblocksSigner {
    api_key: String,
    signing_key: Arc<jsonwebtoken::EncodingKey>,
    vault_account_id: String,
    asset_id: String,
    public_key: Option<Pubkey>,
    api_base_url: String,
    client: reqwest::Client,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
    use_program_call: bool,
}

impl std::fmt::Debug for FireblocksSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FireblocksSigner")
            .field("public_key", &self.public_key)
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("use_program_call", &self.use_program_call)
            .finish_non_exhaustive()
    }
}

/// Configuration for creating a FireblocksSigner
#[derive(Clone)]
pub struct FireblocksSignerConfig {
    pub api_key: String,
    pub private_key_pem: String,
    pub vault_account_id: String,
    /// Asset ID (default: "SOL", use "SOL_TEST" for devnet)
    pub asset_id: Option<String>,
    pub api_base_url: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_poll_attempts: Option<u32>,
    /// Sign transactions with the PROGRAM_CALL operation instead of RAW.
    ///
    /// PROGRAM_CALL is sent with `signOnly: true` and `useDurableNonce: false`,
    /// so Fireblocks signs the submitted transaction without broadcasting it and
    /// without rewriting the message. The returned signature is verified against
    /// the vault public key over the local message bytes before it is used, and
    /// the transaction is broadcast by the caller as in RAW mode.
    ///
    /// PROGRAM_CALL accepts legacy and v0 messages only, requires a hot wallet,
    /// and must be enabled for the workspace by Fireblocks.
    ///
    /// Default: `false` (RAW signing).
    pub use_program_call: Option<bool>,
    /// Optional HTTP client timeout config.
    pub http_client_config: Option<HttpClientConfig>,
}

impl FireblocksSigner {
    /// Create a new FireblocksSigner
    ///
    /// Note: You must call `init()` after construction to fetch the public key.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the signer
    pub fn new(config: FireblocksSignerConfig) -> Result<Self, SignerError> {
        Self::from_config(config)
    }

    /// Create a new FireblocksSigner from a configuration object.
    pub fn from_config(config: FireblocksSignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config.build_client()?;
        let signing_key = Arc::new(jwt::parse_encoding_key(&config.private_key_pem)?);

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

        Ok(Self {
            api_key: config.api_key,
            signing_key,
            vault_account_id: config.vault_account_id,
            asset_id: config.asset_id.unwrap_or_else(|| "SOL".to_string()),
            public_key: None,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.fireblocks.io".to_string()),
            client,
            poll_interval_ms,
            max_poll_attempts,
            use_program_call: config.use_program_call.unwrap_or(false),
        })
    }

    /// Initialize the signer by fetching the public key from Fireblocks
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let pubkey = self.fetch_public_key().await?;
        self.public_key = Some(pubkey);
        Ok(())
    }

    fn initialized_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.public_key.ok_or_else(|| {
            SignerError::ConfigError(
                "FireblocksSigner is not initialized; call init() before signing".to_string(),
            )
        })
    }

    fn create_auth_token(&self, uri: &str, body: &str) -> Result<String, SignerError> {
        jwt::create_jwt(&self.api_key, &self.signing_key, uri, body)
    }

    /// Fetch the public key from Fireblocks vault account addresses
    async fn fetch_public_key(&self) -> Result<Pubkey, SignerError> {
        let uri = format!(
            "/v1/vault/accounts/{}/{}/addresses_paginated",
            self.vault_account_id, self.asset_id
        );
        let token = self.create_auth_token(&uri, "")?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let addresses_response: VaultAddressesResponse =
            parse_json_response(response, "Fireblocks API fetch_public_key").await?;

        let address = self.select_vault_address(&addresses_response.addresses)?;

        Pubkey::from_str(&address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid public key from Fireblocks".to_string())
        })
    }

    /// Pick the address for the configured asset, failing on an empty or
    /// ambiguous response: a mistyped vault account or asset id must not yield a
    /// working signer bound to an unintended fee payer. Entries without an
    /// `assetId` are kept, since the endpoint is already scoped by asset.
    fn select_vault_address(&self, addresses: &[VaultAddress]) -> Result<String, SignerError> {
        let mut unique: Vec<&str> = Vec::with_capacity(addresses.len());
        for entry in addresses {
            if entry.address.is_empty() {
                continue;
            }
            if let Some(asset_id) = entry.asset_id.as_deref() {
                if !asset_id.is_empty() && asset_id != self.asset_id {
                    continue;
                }
            }
            if !unique.contains(&entry.address.as_str()) {
                unique.push(&entry.address);
            }
        }
        match unique.as_slice() {
            [address] => Ok((*address).to_string()),
            [] => Err(SignerError::InvalidPublicKey(format!(
                "Fireblocks returned no address for vault account {} asset {}",
                self.vault_account_id, self.asset_id
            ))),
            _ => Err(SignerError::InvalidPublicKey(format!(
                "Fireblocks returned {} addresses for vault account {} asset {}; cannot choose a signing identity",
                unique.len(),
                self.vault_account_id,
                self.asset_id
            ))),
        }
    }

    /// Sign raw bytes using RAW operation
    async fn sign_raw_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;

        let hex_message = hex::encode(message);

        let request = CreateTransactionRequest {
            asset_id: self.asset_id.clone(),
            operation: "RAW".to_string(),
            source: TransactionSource {
                source_type: "VAULT_ACCOUNT".to_string(),
                id: self.vault_account_id.clone(),
            },
            extra_parameters: Some(ExtraParameters::Raw(RawExtraParameters {
                raw_message_data: RawMessageData {
                    messages: vec![RawMessage {
                        content: hex_message,
                    }],
                },
            })),
        };

        let create_response = self.create_transaction(request).await?;
        let tx_response = self
            .poll_for_completion(&create_response.id, SigningMode::Raw)
            .await?;
        let sig = self.signature_from_signed_messages(&tx_response)?;
        verify_or_reject(&sig, &public_key, message)?;

        Ok(sig)
    }

    /// Sign a transaction with the PROGRAM_CALL operation in sign-only mode.
    ///
    /// Fireblocks returns the signature either in `signedMessages` or as the
    /// `txHash` of the signed transaction, so both carriers are accepted and the
    /// candidate bytes are verified against the vault public key over the local
    /// message before use.
    async fn sign_program_call(
        &self,
        transaction: &VersionedTransaction,
        message_bytes: &[u8],
    ) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;

        if transaction_util::is_v1_message(transaction) {
            return Err(SignerError::SigningFailed(
                "Fireblocks PROGRAM_CALL accepts legacy and v0 messages only; a v1 message cannot be signed in this mode".to_string(),
            ));
        }

        let request = CreateTransactionRequest {
            asset_id: self.asset_id.clone(),
            operation: "PROGRAM_CALL".to_string(),
            source: TransactionSource {
                source_type: "VAULT_ACCOUNT".to_string(),
                id: self.vault_account_id.clone(),
            },
            extra_parameters: Some(ExtraParameters::ProgramCall(ProgramCallExtraParameters {
                program_call_data: TransactionUtil::serialize_transaction(transaction)?,
                sign_only: true,
                use_durable_nonce: false,
            })),
        };

        let create_response = self.create_transaction(request).await?;
        let tx_response = self
            .poll_for_completion(&create_response.id, SigningMode::ProgramCall)
            .await?;

        let sig = match self.signature_from_signed_messages(&tx_response) {
            Ok(sig) => sig,
            Err(no_signed_messages) => match tx_response.tx_hash.as_deref() {
                Some(tx_hash) => signature_from_base58(tx_hash)?,
                None => return Err(no_signed_messages),
            },
        };

        if !sig.verify(&public_key.to_bytes(), message_bytes) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the signature returned for the PROGRAM_CALL does not match the vault public key over the submitted message".to_string(),
            ));
        }

        Ok(sig)
    }

    /// Create a transaction (signing request) in Fireblocks
    async fn create_transaction(
        &self,
        request: CreateTransactionRequest,
    ) -> Result<CreateTransactionResponse, SignerError> {
        let uri = "/v1/transactions";
        let body = serde_json::to_string(&request)?;
        let token = self.create_auth_token(uri, &body)?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .body(body)
            .send()
            .await?;

        parse_json_response(response, "Fireblocks API create_transaction").await
    }

    /// Poll for transaction completion
    async fn poll_for_completion(
        &self,
        tx_id: &str,
        mode: SigningMode,
    ) -> Result<TransactionResponse, SignerError> {
        poll_until(
            self.max_poll_attempts,
            self.poll_interval_ms,
            || {
                SignerError::RemoteApiError(format!(
                    "Transaction polling timeout after {} attempts - signing request may still complete",
                    self.max_poll_attempts
                ))
            },
            || async {
                let response = self.get_transaction(tx_id).await?;

                match (mode, response.status.as_str()) {
                    (SigningMode::ProgramCall, "SIGNED") | (SigningMode::Raw, "COMPLETED") => {
                        Ok(PollOutcome::Done(response))
                    }
                    (SigningMode::ProgramCall, "BROADCASTING" | "CONFIRMING" | "COMPLETED") => {
                        Err(SignerError::BroadcastUnconfirmed {
                            provider_tx_id: Some(tx_id.to_string()),
                            provider_status: None,
                            detail: format!(
                                "Fireblocks broadcast the PROGRAM_CALL despite signOnly (status {}); the transaction may already be executing",
                                response.status
                            ),
                        })
                    }
                    (_, "FAILED" | "CANCELLED" | "REJECTED" | "BLOCKED") => {
                        #[cfg(feature = "unsafe-debug")]
                        log::error!("Transaction failed: {:?}", response);

                        Err(SignerError::SigningFailed(format!(
                            "Transaction {}: {}",
                            response.status, tx_id
                        )))
                    }
                    _ => Ok(PollOutcome::Pending),
                }
            },
        )
        .await
    }

    /// Get transaction status
    async fn get_transaction(&self, tx_id: &str) -> Result<TransactionResponse, SignerError> {
        let uri = format!("/v1/transactions/{}", tx_id);
        let token = self.create_auth_token(&uri, "")?;

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        parse_json_response(response, "Fireblocks API get_transaction").await
    }

    /// Extract the signer-bound signature from a signing response.
    fn signature_from_signed_messages(
        &self,
        response: &TransactionResponse,
    ) -> Result<Signature, SignerError> {
        if let Some(signed_message) = response.signed_messages.first() {
            return signature_from_hex(&signed_message.signature.full_sig);
        }

        Err(SignerError::SigningFailed(
            "No reusable signature found in response (no signed_messages)".to_string(),
        ))
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;
        let message_bytes = transaction.message.serialize();
        let signature = if self.use_program_call {
            self.sign_program_call(transaction, &message_bytes).await?
        } else {
            self.sign_raw_bytes(&message_bytes).await?
        };

        TransactionUtil::add_signature_to_transaction(transaction, &public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if Fireblocks API is available
    async fn check_availability(&self) -> bool {
        if self.public_key.is_none() {
            return false;
        }

        let uri = format!("/v1/vault/accounts/{}", self.vault_account_id);
        let token = match self.create_auth_token(&uri, "") {
            Ok(t) => t,
            Err(_) => return false,
        };

        let url = format!("{}{}", self.api_base_url, uri);
        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FireblocksSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key.expect("FireblocksSigner not initialized")
    }

    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_raw_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        tokio::time::timeout(AVAILABILITY_TIMEOUT, self.check_availability())
            .await
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests;
