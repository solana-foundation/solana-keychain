//! Fordefi API signer integration
//!
//! Fordefi is an institutional MPC custody provider. Transaction signing is async:
//! submit a transaction via POST, then poll GET until the MPC signing completes.
//! API requests require ECDSA P-256 request-level signing.

mod request_signer;
mod types;

use base64::{engine::general_purpose::STANDARD, Engine};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SignerError;
use crate::http_client_config::HttpClientConfig;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner};
use crate::transaction_util::TransactionUtil;
pub use request_signer::{FordefiRequestSigner, PemRequestSigner};
use types::{
    BlackBoxDetails, BlackBoxSignatureRequest, CreateTransactionResponse, SolanaMessageDetails,
    SolanaMessageRequest, SolanaTransactionDetails, SolanaTransactionRequest,
    TransactionStatusResponse, VaultResponse,
};
pub use types::{FordefiPriorityLevel, FordefiSolanaFee, SolanaChainUniqueId};

const DEFAULT_BASE_URL: &str = "https://api.fordefi.com";
const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 50;
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const VAULT_VERIFICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Configuration for creating a FordefiSigner.
#[derive(Clone)]
pub struct FordefiSignerConfig {
    /// Fordefi API bearer token
    pub access_token: String,
    /// Fordefi vault UUID
    pub vault_id: String,
    /// PEM-encoded ECDSA P-256 private key for API request signing.
    /// Provide exactly one of `private_key_pem` or `request_signer`.
    pub private_key_pem: Option<String>,
    /// Custom API-request signer (e.g. a KMS/HSM-backed implementation).
    /// Provide exactly one of `private_key_pem` or `request_signer`.
    pub request_signer: Option<Arc<dyn FordefiRequestSigner>>,
    /// Solana public key of the vault (base58)
    pub public_key: String,
    /// Optional API base URL (default: "https://api.fordefi.com")
    pub api_base_url: Option<String>,
    /// Non-zero polling interval in milliseconds (default: 2000)
    pub poll_interval_ms: Option<u64>,
    /// Non-zero max polling attempts (default: 50)
    pub max_poll_attempts: Option<u32>,
    /// Optional HTTP client config for timeouts
    pub http_client_config: Option<HttpClientConfig>,
    /// When set, uses native Solana API types instead of black_box_signature.
    /// Use `SolanaDevnet` or `SolanaMainnet`.
    pub chain: Option<SolanaChainUniqueId>,
    /// Fee configuration for native Solana transactions (only used when `chain` is set).
    pub fee: Option<FordefiSolanaFee>,
}

/// Fordefi-based signer using Fordefi's MPC custody API.
///
/// Supports two signing modes, which differ in what `sign_transaction` returns:
/// - **Black box** (default, `chain` = `None`): Signs raw bytes via `black_box_signature`
///   and returns nothing else. Fordefi does **not** broadcast; the returned serialized
///   transaction is the locally-assembled signed tx, which the caller submits to an RPC.
/// - **Native Solana** (`chain` = `Some(...)`): Uses `solana_transaction` / `solana_message`
///   API types. Fordefi will modify the transaction (at minimum updating the blockhash,
///   and optionally adding priority fees) and **auto-broadcasts** it on-chain
///   (`push_mode: "auto"`). Because the transaction is already submitted, the returned
///   serialized transaction is **empty** — only the signature, the on-chain
///   identifier, is returned. The caller's `&mut Transaction` is left untouched.
pub struct FordefiSigner {
    access_token: String,
    vault_id: String,
    request_signer: Arc<dyn FordefiRequestSigner>,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
    chain: Option<SolanaChainUniqueId>,
    fee: Option<FordefiSolanaFee>,
}

impl std::fmt::Debug for FordefiSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FordefiSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl FordefiSigner {
    /// Create a new FordefiSigner from a configuration object.
    ///
    /// Fetches the configured Fordefi vault and verifies that its authoritative
    /// Solana public key matches `config.public_key` before returning.
    ///
    /// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    /// key in `config.private_key_pem`, or a custom [`FordefiRequestSigner`] in
    /// `config.request_signer` for KMS/HSM-backed signing.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let signer = Self::build(config)?;
        signer.verify_vault_address_with_timeout().await?;
        Ok(signer)
    }

    /// Shared construction: validate config, resolve the request-signing
    /// mechanism, and assemble the signer.
    fn build(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        if config.access_token.is_empty() {
            return Err(SignerError::ConfigError(
                "access_token must not be empty".to_string(),
            ));
        }

        if config.vault_id.is_empty() {
            return Err(SignerError::ConfigError(
                "vault_id must not be empty".to_string(),
            ));
        }

        if config.public_key.is_empty() {
            return Err(SignerError::ConfigError(
                "public_key must not be empty".to_string(),
            ));
        }

        let request_signer: Arc<dyn FordefiRequestSigner> =
            match (&config.private_key_pem, &config.request_signer) {
                (Some(_), Some(_)) => {
                    return Err(SignerError::ConfigError(
                        "provide exactly one of private_key_pem or request_signer, not both"
                            .to_string(),
                    ));
                }
                (None, None) => {
                    return Err(SignerError::ConfigError(
                        "one of private_key_pem or request_signer must be provided".to_string(),
                    ));
                }
                (Some(private_key_pem), None) => {
                    Arc::new(PemRequestSigner::from_pem(private_key_pem)?)
                }
                (None, Some(request_signer)) => Arc::clone(request_signer),
            };

        let api_base_url = config
            .api_base_url
            .as_deref()
            .unwrap_or(DEFAULT_BASE_URL)
            .trim_end_matches('/')
            .to_string();
        let parsed_api_base_url = reqwest::Url::parse(&api_base_url).map_err(|_| {
            SignerError::ConfigError("api_base_url must be a valid URL".to_string())
        })?;

        #[cfg(test)]
        let test_loopback_http = parsed_api_base_url.scheme() == "http"
            && matches!(
                parsed_api_base_url.host_str(),
                Some("127.0.0.1" | "localhost" | "::1")
            );
        #[cfg(not(test))]
        let test_loopback_http = false;

        if parsed_api_base_url.scheme() != "https" && !test_loopback_http {
            return Err(SignerError::ConfigError(
                "api_base_url must use HTTPS".to_string(),
            ));
        }

        if config.fee.is_some() && config.chain.is_none() {
            return Err(SignerError::ConfigError(
                "fee requires chain to be set (native Solana mode)".to_string(),
            ));
        }

        let poll_interval_ms = config.poll_interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS);
        if poll_interval_ms == 0 {
            return Err(SignerError::ConfigError(
                "poll_interval_ms must be greater than zero".to_string(),
            ));
        }

        let max_poll_attempts = config
            .max_poll_attempts
            .unwrap_or(DEFAULT_MAX_POLL_ATTEMPTS);
        if max_poll_attempts == 0 {
            return Err(SignerError::ConfigError(
                "max_poll_attempts must be greater than zero".to_string(),
            ));
        }

        let public_key = Pubkey::from_str(&config.public_key)
            .map_err(|_| SignerError::InvalidPublicKey("Invalid Solana public key".to_string()))?;

        let http = config.http_client_config.unwrap_or_default();
        let client = http.build_client()?;

        Ok(Self {
            access_token: config.access_token,
            vault_id: config.vault_id,
            request_signer,
            api_base_url,
            client,
            public_key,
            poll_interval_ms,
            max_poll_attempts,
            chain: config.chain,
            fee: config.fee,
        })
    }

    /// Sign an API request payload via the configured [`FordefiRequestSigner`].
    ///
    /// Payload format: `{path}|{timestamp}|{body}`
    async fn sign_request(
        &self,
        path: &str,
        timestamp: u64,
        body: &str,
    ) -> Result<String, SignerError> {
        let payload = format!("{path}|{timestamp}|{body}");
        self.request_signer.sign_request(payload.as_bytes()).await
    }

    // -----------------------------------------------------------------------
    // Submit helpers
    // -----------------------------------------------------------------------

    /// POST a serialized request body to `/api/v1/transactions` with P-256
    /// request signing. Returns the Fordefi transaction ID.
    async fn submit_request<T: serde::Serialize>(
        &self,
        request: &T,
        idempotence_id: Option<&str>,
    ) -> Result<String, SignerError> {
        let path = "/api/v1/transactions";
        let body = serde_json::to_string(request)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SignerError::Other(format!("System time error: {e}")))?
            .as_millis() as u64;
        let signature = self.sign_request(path, timestamp, &body).await?;

        let url = format!("{}{}", self.api_base_url, path);
        let mut builder = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("x-signature", &signature)
            .header("x-timestamp", timestamp.to_string())
            .header("Content-Type", "application/json");
        if let Some(id) = idempotence_id {
            builder = builder.header("x-idempotence-id", id);
        }
        let response = builder.body(body).send().await?;

        if !response.status().is_success() {
            return Err(Self::extract_api_error(response, "submit_request").await);
        }

        let create_response: CreateTransactionResponse = response.json().await?;
        Ok(create_response.id)
    }

    /// Submit a black_box_signature request for raw EdDSA signing.
    async fn submit_black_box_signature(&self, data_bytes: &[u8]) -> Result<String, SignerError> {
        let base64_data = STANDARD.encode(data_bytes);

        let request = BlackBoxSignatureRequest {
            vault_id: self.vault_id.clone(),
            signer_type: "api_signer",
            sign_mode: "auto",
            tx_type: "black_box_signature",
            details: BlackBoxDetails {
                format: "hash_binary",
                hash_binary: base64_data,
            },
        };

        self.submit_request(&request, None).await
    }

    /// Submit a native Solana transaction request.
    async fn submit_solana_transaction(&self, data_bytes: &[u8]) -> Result<String, SignerError> {
        let chain = self.chain.as_ref().ok_or_else(|| {
            SignerError::ConfigError("chain must be set for native Solana transactions".to_string())
        })?;
        let base64_data = STANDARD.encode(data_bytes);

        let request = SolanaTransactionRequest {
            vault_id: self.vault_id.clone(),
            signer_type: "api_signer",
            sign_mode: "auto",
            tx_type: "solana_transaction",
            details: SolanaTransactionDetails {
                detail_type: "solana_serialized_transaction_message",
                chain: chain.clone(),
                data: base64_data,
                push_mode: "auto",
                fee: self.fee.clone(),
            },
        };

        self.submit_request(
            &request,
            Some(&crate::transaction_util::idempotency_key_from_message(
                data_bytes,
            )),
        )
        .await
    }

    /// Submit a native Solana message request.
    async fn submit_solana_message(&self, message_bytes: &[u8]) -> Result<String, SignerError> {
        let chain = self.chain.as_ref().ok_or_else(|| {
            SignerError::ConfigError("chain must be set for native Solana messages".to_string())
        })?;
        let base64_data = STANDARD.encode(message_bytes);

        let request = SolanaMessageRequest {
            vault_id: self.vault_id.clone(),
            signer_type: "api_signer",
            sign_mode: "auto",
            tx_type: "solana_message",
            details: SolanaMessageDetails {
                detail_type: "personal_message_type",
                chain: chain.clone(),
                raw_data: base64_data,
            },
        };

        self.submit_request(&request, None).await
    }

    // -----------------------------------------------------------------------
    // Polling
    // -----------------------------------------------------------------------

    /// Poll until the transaction reaches a terminal state.
    ///
    /// When `pushable` is true (native Solana transactions), the only terminal
    /// success state is `completed` (in Fordefi's `finalized` aggregate). When
    /// false (black box / messages), the terminal success state is `signed`
    /// (also accepting `completed` defensively).
    async fn poll_for_result(
        &self,
        tx_id: &str,
        pushable: bool,
    ) -> Result<TransactionStatusResponse, SignerError> {
        for attempt in 0..self.max_poll_attempts {
            let url = format!("{}/api/v1/transactions/{}", self.api_base_url, tx_id);
            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.access_token))
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(Self::extract_api_error(response, "poll_result").await);
            }

            let tx_data: TransactionStatusResponse = response.json().await?;

            let is_success = if pushable {
                matches!(tx_data.state.as_str(), "completed")
            } else {
                matches!(tx_data.state.as_str(), "signed" | "completed")
            };

            if is_success {
                return Ok(tx_data);
            }

            let is_error = matches!(
                tx_data.state.as_str(),
                "aborted"
                    | "cancelled"
                    | "dropped"
                    | "completed_reverted"
                    | "error_pushing_to_blockchain"
                    | "error_signing"
                    | "insufficient_funds"
                    | "mined_reverted"
            );

            if is_error {
                return Err(SignerError::SigningFailed(format!(
                    "Transaction {} reached terminal state: {}",
                    tx_id, tx_data.state
                )));
            }

            // Skip the sleep on the final attempt so we don't delay the timeout error.
            if attempt + 1 < self.max_poll_attempts {
                tokio::time::sleep(tokio::time::Duration::from_millis(self.poll_interval_ms)).await;
            }
        }

        Err(SignerError::RemoteApiError(format!(
            "Polling timeout after {} attempts",
            self.max_poll_attempts
        )))
    }

    /// Extract and validate a 64-byte Ed25519 signature from a poll response.
    fn extract_signature_from_result(
        result: &TransactionStatusResponse,
    ) -> Result<Signature, SignerError> {
        let entry = result
            .signatures
            .as_ref()
            .and_then(|sigs| sigs.first())
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Transaction signed but no signatures in response".to_string(),
                )
            })?;

        let sig_bytes = STANDARD.decode(&entry.data).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode signature base64: {e}"))
        })?;

        if sig_bytes.len() != 64 {
            return Err(SignerError::SigningFailed(format!(
                "Expected 64-byte Ed25519 signature, got {}",
                sig_bytes.len()
            )));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        Ok(Signature::from(sig_array))
    }

    /// Poll for a non-pushable result and extract the 64-byte signature.
    async fn poll_for_signature(&self, tx_id: &str) -> Result<Signature, SignerError> {
        let result = self.poll_for_result(tx_id, false).await?;
        Self::extract_signature_from_result(&result)
    }

    // -----------------------------------------------------------------------
    // Signing paths
    // -----------------------------------------------------------------------

    /// Sign raw bytes via the black box path: submit → poll → extract signature.
    async fn sign_black_box(&self, data: &[u8]) -> Result<Signature, SignerError> {
        let tx_id = self.submit_black_box_signature(data).await?;
        self.poll_for_signature(&tx_id).await
    }

    /// Sign a transaction via the black box path: submit → poll → apply signature.
    async fn sign_and_serialize_black_box(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message.serialize();
        let signature = self.sign_black_box(&message_data).await?;

        if !signature.verify(&self.public_key.to_bytes(), &message_data) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed".to_string(),
            ));
        }

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Sign a transaction via the native Solana path: submit → poll → parse wire tx.
    ///
    /// Fordefi will modify the transaction (at minimum updating the blockhash, and
    /// optionally adding priority fees), so we verify the signature against the
    /// returned message bytes, not the original. The caller's `transaction` is
    /// left untouched.
    ///
    /// Because native mode uses `push_mode: "auto"`, Fordefi has already broadcast
    /// the transaction on-chain by the time this returns. Re-sending it would be
    /// superfluous, so the returned serialized-transaction string is intentionally
    /// empty — only the signature, usable with RPC transaction lookups, is
    /// returned.
    ///
    /// Each native create carries an `x-idempotence-id` derived from the message
    /// bytes, so retrying the exact same bytes cannot create a second transaction.
    ///
    /// Only legacy transactions are supported: a versioned (v0) transaction
    /// returned by Fordefi fails to deserialize with a [`SignerError::SerializationError`].
    async fn sign_and_serialize_native(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.validate_native_auto_transaction(transaction)?;
        let message_data = transaction.message.serialize();
        let tx_id = self.submit_solana_transaction(&message_data).await?;
        // Once the submit is accepted Fordefi is already broadcasting
        // (push_mode: "auto"), so any later failure leaves an on-chain outcome
        // this client cannot rule out. Report those as BroadcastUnconfirmed
        // carrying the Fordefi transaction id instead of a generic error a
        // caller might blindly retry into a duplicate spend.
        self.finish_native_broadcast(&tx_id).await.map_err(|error| {
            SignerError::BroadcastUnconfirmed {
                provider_tx_id: tx_id,
                detail: error.detail_string(),
            }
        })
    }

    async fn finish_native_broadcast(&self, tx_id: &str) -> Result<SignedTransaction, SignerError> {
        let result = self.poll_for_result(tx_id, true).await?;

        let raw_tx_b64 = result.raw_transaction.as_ref().ok_or_else(|| {
            SignerError::SigningFailed(
                "Fordefi solana_transaction response missing raw_transaction".to_string(),
            )
        })?;

        let wire_bytes = STANDARD.decode(raw_tx_b64).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode raw_transaction base64: {e}"))
        })?;

        // Deserialize the Fordefi-returned wire transaction with the Solana SDK
        // (bincode of a Transaction is exactly the Solana wire format).
        //
        // NOTE: only *legacy* transactions are supported. A versioned (v0) wire
        // transaction is prefixed with a version byte (high bit set on the first
        // byte) that the legacy `Transaction` layout cannot represent, so if Fordefi
        // ever returns a v0 transaction this deserialization fails rather than
        // silently mis-parsing. Supporting v0 would mean decoding into
        // `VersionedTransaction` and threading that type through the signer API.
        let returned_tx: VersionedTransaction =
            crate::transaction_util::deserialize_wire_transaction(&wire_bytes).map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to deserialize Fordefi wire transaction (versioned/v0 \
                 transactions are not supported, only legacy): {e}"
                ))
            })?;

        let signature = self.extract_vault_signature(&returned_tx)?;

        // Verify against the *returned* message (Fordefi modifies the tx, e.g. blockhash)
        let returned_message = returned_tx.message.serialize();
        if !signature.verify(&self.public_key.to_bytes(), &returned_message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed against Fordefi-returned message".to_string(),
            ));
        }

        // Auto-broadcast leaves nothing to send; the signature is the on-chain
        // identifier and the caller's transaction stays untouched.
        Ok((String::new(), signature))
    }

    /// Native auto-broadcast currently submits message bytes only. Transactions
    /// with additional required signers would also need their partial signatures
    /// forwarded through Fordefi's `details.signatures` request field.
    fn validate_native_auto_transaction(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<(), SignerError> {
        let required_signatures = transaction.message.header().num_required_signatures as usize;
        if required_signatures != 1
            || transaction.message.static_account_keys().first() != Some(&self.public_key)
        {
            return Err(SignerError::SigningFailed(
                "Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Locate the configured vault's signature by its required-signer account
    /// position rather than assuming it occupies slot zero.
    fn extract_vault_signature(
        &self,
        returned_tx: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        let signer_index =
            TransactionUtil::get_signing_keypair_position(returned_tx, &self.public_key)?;
        returned_tx
            .signatures
            .get(signer_index)
            .copied()
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Fordefi signature slot missing from returned transaction".to_string(),
                )
            })
    }

    /// Sign a transaction end-to-end, dispatching to black box or native path.
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        if self.chain.is_some() {
            self.sign_and_serialize_native(transaction).await
        } else {
            self.sign_and_serialize_black_box(transaction).await
        }
    }

    /// Fetch the configured vault from Fordefi.
    async fn fetch_vault(&self) -> Result<VaultResponse, SignerError> {
        let url = format!("{}/api/v1/vaults/{}", self.api_base_url, self.vault_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::extract_api_error(response, "fetch_vault").await);
        }

        Ok(response.json().await?)
    }

    /// Resolve the authoritative Solana public key returned for a Fordefi vault.
    ///
    /// Chain-specific vaults expose a base58 `address`; black-box vaults expose
    /// the same 32-byte Ed25519 public key as base64 in `public_key_compressed`.
    fn vault_public_key(vault: &VaultResponse) -> Result<Pubkey, SignerError> {
        if let Some(address) = vault
            .address
            .as_deref()
            .filter(|address| !address.is_empty())
        {
            return Pubkey::from_str(address).map_err(|_| {
                SignerError::InvalidPublicKey(
                    "Fordefi vault returned an invalid Solana address".to_string(),
                )
            });
        }

        let public_key_compressed = vault.public_key_compressed.as_deref().ok_or_else(|| {
            SignerError::ConfigError(
                "Fordefi vault response included neither `address` nor \
                 `public_key_compressed`; cannot verify public_key ownership"
                    .to_string(),
            )
        })?;
        let public_key_bytes = STANDARD.decode(public_key_compressed).map_err(|_| {
            SignerError::SerializationError(
                "Failed to decode Fordefi vault public_key_compressed as base64".to_string(),
            )
        })?;
        let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
            SignerError::InvalidPublicKey(
                "Fordefi vault public_key_compressed must decode to 32 bytes".to_string(),
            )
        })?;

        Ok(Pubkey::new_from_array(public_key_bytes))
    }

    /// Verify that the configured public key belongs to the configured Fordefi vault.
    async fn verify_vault_address(&self) -> Result<(), SignerError> {
        let vault = self.fetch_vault().await?;
        let remote_public_key = Self::vault_public_key(&vault)?;

        if remote_public_key != self.public_key {
            return Err(SignerError::ConfigError(format!(
                "Configured public_key does not match Fordefi vault {}",
                self.vault_id
            )));
        }

        Ok(())
    }

    async fn verify_vault_address_with_timeout(&self) -> Result<(), SignerError> {
        tokio::time::timeout(VAULT_VERIFICATION_TIMEOUT, self.verify_vault_address())
            .await
            .map_err(|_| {
                SignerError::HttpError(format!(
                    "Fordefi vault verification timed out after {} seconds",
                    VAULT_VERIFICATION_TIMEOUT.as_secs()
                ))
            })?
    }

    async fn extract_api_error(response: reqwest::Response, context: &str) -> SignerError {
        let status = response.status().as_u16();

        #[cfg(feature = "unsafe-debug")]
        {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            log::error!("Fordefi API {context} error - status: {status}, response: {error_text}");
        }

        #[cfg(not(feature = "unsafe-debug"))]
        {
            let _ = response;
            log::error!("Fordefi API {context} error - status: {status}");
        }

        SignerError::RemoteApiError(format!("API error {status}"))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FordefiSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    fn broadcasts_transactions(&self) -> bool {
        self.chain.is_some()
    }

    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        if self.chain.is_some() {
            // Native mode has already broadcast the transaction, so it is
            // complete regardless of the caller's untouched signature slots.
            return Ok(SignTransactionResult::Complete(signed_transaction));
        }
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let signature = if self.chain.is_some() {
            let tx_id = self.submit_solana_message(message).await?;
            self.poll_for_signature(&tx_id).await?
        } else {
            self.sign_black_box(message).await?
        };

        if !signature.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed".to_string(),
            ));
        }

        Ok(signature)
    }

    async fn is_available(&self) -> bool {
        let readiness_check = async {
            self.fetch_vault().await?;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| SignerError::Other(format!("System time error: {e}")))?
                .as_millis() as u64;
            self.sign_request("/api/v1/vaults", timestamp, "").await?;
            Ok::<(), SignerError>(())
        };
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, readiness_check).await;
        matches!(result, Ok(Ok(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::{keypair_pubkey, Keypair, Signer as SdkSigner};
    use crate::test_util::create_test_transaction;
    use p256::ecdsa::SigningKey;
    use wiremock::{
        matchers::{header, method, path, path_regex},
        Mock, MockServer, ResponseTemplate,
    };

    fn create_test_keypair() -> Keypair {
        Keypair::new()
    }

    /// Generate a test PEM key string (SEC1-encoded ECDSA P-256).
    fn test_pem_key() -> String {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let secret_key: p256::SecretKey = signing_key.into();
        secret_key
            .to_sec1_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn test_request_signer() -> Arc<dyn FordefiRequestSigner> {
        Arc::new(PemRequestSigner::from_pem(&test_pem_key()).unwrap())
    }

    /// Exercise the synchronous local-validation/build phase without the public
    /// constructor's authoritative Fordefi vault round-trip.
    fn build_test_signer_from_config(
        config: FordefiSignerConfig,
    ) -> Result<FordefiSigner, SignerError> {
        FordefiSigner::build(config)
    }

    /// `from_config` against a plain-HTTP wiremock server: the production
    /// client is HTTPS-only, so the vault round-trip needs a test client
    /// (which keeps the no-redirect policy).
    async fn from_config_with_test_client(
        config: FordefiSignerConfig,
    ) -> Result<FordefiSigner, SignerError> {
        let mut signer = FordefiSigner::build(config)?;
        signer.client = reqwest::Client::builder()
            .redirect(crate::http_client_config::no_redirect_policy())
            .build()
            .expect("Failed to build test HTTP client");
        signer.verify_vault_address_with_timeout().await?;
        Ok(signer)
    }

    fn base_test_config() -> FordefiSignerConfig {
        FordefiSignerConfig {
            access_token: "test-token".to_string(),
            vault_id: "test-vault-id".to_string(),
            private_key_pem: Some(test_pem_key()),
            request_signer: None,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        }
    }

    fn verified_test_config(base_url: &str, public_key: Pubkey) -> FordefiSignerConfig {
        FordefiSignerConfig {
            public_key: public_key.to_string(),
            api_base_url: Some(base_url.to_string()),
            poll_interval_ms: Some(10),
            max_poll_attempts: Some(3),
            ..base_test_config()
        }
    }

    /// Build a FordefiSigner for tests with the given request signer and chain.
    fn create_test_signer_with(
        base_url: &str,
        pubkey: Pubkey,
        request_signer: Arc<dyn FordefiRequestSigner>,
        chain: Option<SolanaChainUniqueId>,
    ) -> FordefiSigner {
        FordefiSigner {
            access_token: "test-token".to_string(),
            vault_id: "test-vault-id".to_string(),
            request_signer,
            api_base_url: base_url.to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            public_key: pubkey,
            poll_interval_ms: 10,
            max_poll_attempts: 3,
            chain,
            fee: None,
        }
    }

    /// Helper to build a black-box FordefiSigner for tests with a mock server URL.
    fn create_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
        create_test_signer_with(base_url, pubkey, test_request_signer(), None)
    }

    /// Helper to build a native-Solana FordefiSigner for tests.
    fn create_native_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
        create_test_signer_with(
            base_url,
            pubkey,
            test_request_signer(),
            Some(SolanaChainUniqueId::SolanaMainnet),
        )
    }

    #[test]
    fn test_broadcasts_transactions_by_mode() {
        let pubkey = Pubkey::new_unique();
        assert!(!create_test_signer("https://example.com", pubkey).broadcasts_transactions());
        assert!(create_native_test_signer("https://example.com", pubkey).broadcasts_transactions());
    }

    /// Build a mock wire transaction: [1 byte sig_count][64-byte signature][message bytes]
    fn build_mock_wire_transaction(keypair: &Keypair, message_bytes: &[u8]) -> Vec<u8> {
        let signature = keypair.sign_message(message_bytes);
        let sig_bytes = signature.as_ref();
        let mut wire = Vec::with_capacity(1 + 64 + message_bytes.len());
        wire.push(1u8); // sig_count = 1
        wire.extend_from_slice(sig_bytes);
        wire.extend_from_slice(message_bytes);
        wire
    }

    // --- Config validation tests ---

    #[test]
    fn test_fordefi_config_empty_access_token() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            access_token: String::new(),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_empty_vault_id() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            vault_id: String::new(),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_invalid_pem() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            private_key_pem: Some("not-a-valid-pem".to_string()),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPrivateKey(_)
        ));
    }

    #[test]
    fn test_fordefi_config_invalid_pubkey() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            public_key: "not-a-pubkey".to_string(),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[test]
    fn test_fordefi_config_rejects_http_url() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            api_base_url: Some("http://insecure.example.com".to_string()),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_rejects_malformed_https_url() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            api_base_url: Some("https://".to_string()),
            ..base_test_config()
        });

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_fee_without_chain_rejected() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            fee: Some(FordefiSolanaFee::Priority {
                priority_level: FordefiPriorityLevel::High,
            }),
            ..base_test_config()
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_zero_poll_interval_rejected() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            poll_interval_ms: Some(0),
            ..base_test_config()
        });
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_zero_max_poll_attempts_rejected() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            max_poll_attempts: Some(0),
            ..base_test_config()
        });
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_with_chain_valid() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            chain: Some(SolanaChainUniqueId::SolanaDevnet),
            ..base_test_config()
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_fordefi_config_valid() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        let result = build_test_signer_from_config(FordefiSignerConfig {
            public_key: pubkey_str,
            ..base_test_config()
        });
        assert!(result.is_ok());
        let signer = result.unwrap();
        assert_eq!(signer.api_base_url, "https://api.fordefi.com");
        assert_eq!(signer.public_key, keypair_pubkey(&keypair));
    }

    #[test]
    fn test_fordefi_config_strips_trailing_slash() {
        let result = build_test_signer_from_config(FordefiSignerConfig {
            api_base_url: Some("https://custom.api.com/".to_string()),
            ..base_test_config()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().api_base_url, "https://custom.api.com");
    }

    // --- Authoritative vault verification tests ---

    #[tokio::test]
    async fn test_fordefi_constructor_verifies_chain_specific_vault_address() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": public_key.to_string(),
                "id": "test-vault-id",
                "type": "solana"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await
                .unwrap();

        assert_eq!(signer.pubkey(), public_key);
    }

    #[tokio::test]
    async fn test_fordefi_constructor_derives_black_box_vault_address() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());
        let public_key_compressed = STANDARD.encode(public_key.to_bytes());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-vault-id",
                "public_key_compressed": public_key_compressed,
                "type": "black_box"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await
                .unwrap();

        assert_eq!(signer.pubkey(), public_key);
    }

    #[tokio::test]
    async fn test_fordefi_constructor_rejects_vault_address_mismatch() {
        let mock_server = MockServer::start().await;
        let configured_public_key = keypair_pubkey(&create_test_keypair());
        let remote_public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": remote_public_key.to_string(),
                "id": "test-vault-id"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = from_config_with_test_client(verified_test_config(
            &mock_server.uri(),
            configured_public_key,
        ))
        .await;

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_fordefi_constructor_rejects_vault_without_public_key() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": "test-vault-id" })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let result =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await;

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_fordefi_constructor_rejects_invalid_black_box_public_key() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-vault-id",
                "public_key_compressed": STANDARD.encode([1_u8; 31]),
                "type": "black_box"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await;

        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_constructor_rejects_invalid_black_box_base64() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-vault-id",
                "public_key_compressed": "not-base64",
                "type": "black_box"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await;

        assert!(matches!(
            result.unwrap_err(),
            SignerError::SerializationError(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_constructor_propagates_vault_api_error() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result =
            from_config_with_test_client(verified_test_config(&mock_server.uri(), public_key))
                .await;

        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    // --- sign_message tests ---

    #[tokio::test]
    async fn test_fordefi_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        let message = b"hello fordefi message signing";
        let real_signature = keypair.sign_message(message);
        let sig_b64 = STANDARD.encode(real_signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("Authorization", "Bearer test-token"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "type": "black_box_signature",
                "details": { "format": "hash_binary" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg-1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/msg-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "signatures": [{ "data": sig_b64 }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(result.is_ok(), "sign_message failed: {:?}", result.err());
        assert_eq!(result.unwrap(), real_signature);
    }

    #[tokio::test]
    async fn test_fordefi_sign_message_verification_failure() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        // Mock returns a signature for a *different* message than the one we sign
        let bogus_signature = keypair.sign_message(b"different message");
        let sig_b64 = STANDARD.encode(bogus_signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg-bad"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/msg-bad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "signatures": [{ "data": sig_b64 }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"actual message").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_sign_message_missing_signatures() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg-empty"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/msg-empty"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_sign_message_failed_state() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg-fail"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/msg-fail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "aborted"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    // --- Sign transaction tests ---

    #[tokio::test]
    async fn test_fordefi_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        let tx = create_test_transaction(&pubkey);
        let message_data = tx.message.serialize();
        let real_signature = keypair.sign_message(&message_data);
        let sig_b64 = STANDARD.encode(real_signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("Authorization", "Bearer test-token"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "type": "black_box_signature",
                "details": { "format": "hash_binary" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/tx-123"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "signatures": [{ "data": sig_b64 }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = tx;
        let result = signer.sign_transaction(&mut tx).await;
        assert!(
            result.is_ok(),
            "sign_transaction failed: {:?}",
            result.err()
        );
        let (serialized_tx, _sig) = result.unwrap().into_signed_transaction();
        assert!(!serialized_tx.is_empty());
    }

    #[tokio::test]
    async fn test_fordefi_sign_transaction_failed_state() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-fail"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/tx-fail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "aborted"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_sign_transaction_poll_timeout() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-pending"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Always return pending state
        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/tx-pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "pending_signature"
            })))
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_submit_unauthorized() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "message": "Invalid token"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SignerError::RemoteApiError(_)));
        assert_eq!(err.to_string(), "Remote API error");
    }

    #[tokio::test]
    async fn test_fordefi_sign_transaction_missing_signatures() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "tx-no-sig"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/tx-no-sig"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    // --- is_available tests ---

    #[tokio::test]
    async fn test_fordefi_is_available_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/vaults/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "test-vault-id"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(signer.is_available().await);
    }

    #[tokio::test]
    async fn test_fordefi_is_available_checks_request_signer() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());
        let signer = create_test_signer_with(
            &mock_server.uri(),
            public_key,
            Arc::new(FailingSigner),
            None,
        );

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/vaults/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": "test-vault-id" })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_fordefi_is_available_api_error() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/vaults/.*"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    #[tokio::test]
    async fn test_fordefi_is_available_timeout() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/vaults/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id": "vault" }))
                    .set_delay(std::time::Duration::from_secs(10)),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(!signer.is_available().await);
    }

    // --- Debug ---

    #[test]
    fn test_fordefi_debug_hides_secrets() {
        let keypair = create_test_keypair();
        let signer = create_test_signer("https://test.com", keypair_pubkey(&keypair));

        let debug_str = format!("{:?}", signer);
        assert!(!debug_str.contains("test-token"));
        assert!(!debug_str.contains("test-vault-id"));
        assert!(debug_str.contains("FordefiSigner"));
    }

    #[tokio::test]
    async fn test_fordefi_error_status_code_only() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "message": "Vault is locked"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "Remote API error");
        assert!(!err.to_string().contains("Vault is locked"));
    }

    // --- Native Solana signing tests ---

    #[test]
    fn test_fordefi_native_extracts_vault_signature_from_non_first_slot() {
        let fee_payer = create_test_keypair();
        let fordefi_keypair = create_test_keypair();
        let fordefi_pubkey = keypair_pubkey(&fordefi_keypair);
        let signer = create_native_test_signer("https://test.com", fordefi_pubkey);

        let mut returned_tx = create_test_transaction(&keypair_pubkey(&fee_payer));
        crate::test_util::add_required_signer(&mut returned_tx, fordefi_pubkey);
        let returned_message = returned_tx.message.serialize();
        let fee_payer_signature = fee_payer.sign_message(&returned_message);
        let fordefi_signature = fordefi_keypair.sign_message(&returned_message);
        returned_tx.signatures = vec![fee_payer_signature, fordefi_signature];

        let extracted = signer.extract_vault_signature(&returned_tx).unwrap();
        assert_eq!(extracted, fordefi_signature);
        assert!(extracted.verify(&fordefi_pubkey.to_bytes(), &returned_message));
    }

    #[test]
    fn test_fordefi_native_rejects_multiple_required_signers_before_submit() {
        let fee_payer = create_test_keypair();
        let fordefi_keypair = create_test_keypair();
        let fordefi_pubkey = keypair_pubkey(&fordefi_keypair);
        let signer = create_native_test_signer("https://test.com", fordefi_pubkey);

        let mut tx = create_test_transaction(&keypair_pubkey(&fee_payer));
        crate::test_util::add_required_signer(&mut tx, fordefi_pubkey);

        let result = signer.validate_native_auto_transaction(&tx);
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        let tx = create_test_transaction(&pubkey);
        let message_data = tx.message.serialize();

        let wire_bytes = build_mock_wire_transaction(&keypair, &message_data);
        let wire_b64 = STANDARD.encode(&wire_bytes);

        let expected_idempotence_id =
            crate::transaction_util::idempotency_key_from_message(&message_data);
        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("Authorization", "Bearer test-token"))
            .and(header("x-idempotence-id", expected_idempotence_id.as_str()))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "type": "solana_transaction",
                "details": {
                    "type": "solana_serialized_transaction_message",
                    "push_mode": "auto"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-tx-1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-tx-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "raw_transaction": wire_b64
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = tx;
        let result = signer.sign_transaction(&mut tx).await;
        assert!(
            result.is_ok(),
            "native sign_transaction failed: {:?}",
            result.err()
        );
        let result = result.unwrap();
        assert!(
            matches!(result, SignTransactionResult::Complete(_)),
            "a broadcast native transaction is complete even though the caller's \
             signature slots stay untouched"
        );
        let (serialized_tx, sig) = result.into_signed_transaction();
        // Native mode auto-broadcasts, so no re-sendable wire tx is returned.
        assert!(
            serialized_tx.is_empty(),
            "native mode should return an empty serialized transaction"
        );
        assert!(sig.verify(&pubkey.to_bytes(), &message_data));
        assert!(
            tx.signatures.iter().all(|s| *s == Signature::default()),
            "the caller's transaction must be left untouched by provider-chosen bytes"
        );
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_missing_raw_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-tx-no-raw"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-tx-no-raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        match result.unwrap_err() {
            SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
                assert_eq!(provider_tx_id, "native-tx-no-raw");
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_failed_state() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-tx-fail"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-tx-fail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "aborted"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        match result.unwrap_err() {
            SignerError::BroadcastUnconfirmed {
                provider_tx_id,
                detail,
            } => {
                assert_eq!(provider_tx_id, "native-tx-fail");
                assert!(
                    detail.contains("aborted"),
                    "detail must carry the state, got: {detail}"
                );
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_message_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        let message = b"hello native solana message signing";
        let real_signature = keypair.sign_message(message);
        let sig_b64 = STANDARD.encode(real_signature.as_ref());

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "type": "solana_message",
                "details": { "type": "personal_message_type" }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-msg-1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-msg-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "signed",
                "signatures": [{ "data": sig_b64 }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(
            result.is_ok(),
            "native sign_message failed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), real_signature);
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_message_aborted() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-msg-abort"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-msg-abort"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "aborted"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_poll_timeout_is_broadcast_unconfirmed() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-tx-pending"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-tx-pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "pending_signature"
            })))
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        match result.unwrap_err() {
            SignerError::BroadcastUnconfirmed {
                provider_tx_id,
                detail,
            } => {
                assert_eq!(provider_tx_id, "native-tx-pending");
                assert!(
                    detail.contains("timeout"),
                    "detail must carry the cause, got: {detail}"
                );
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    // --- Wire transaction parsing tests ---

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_malformed_raw_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        // A blob that is not a valid bincode-encoded Solana transaction.
        let bad_wire_b64 = STANDARD.encode([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-tx-malformed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-tx-malformed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "raw_transaction": bad_wire_b64
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        let result = signer.sign_transaction(&mut tx).await;
        match result.unwrap_err() {
            SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
                assert_eq!(provider_tx_id, "native-tx-malformed");
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    // --- Custom request-signer (FordefiRequestSigner) tests ---

    /// A custom request signer that returns a fixed `x-signature` value.
    struct CannedSigner(&'static str);

    #[async_trait::async_trait]
    impl FordefiRequestSigner for CannedSigner {
        async fn sign_request(&self, _payload: &[u8]) -> Result<String, SignerError> {
            Ok(self.0.to_string())
        }
    }

    /// A custom request signer that always fails (e.g. KMS unavailable).
    struct FailingSigner;

    #[async_trait::async_trait]
    impl FordefiRequestSigner for FailingSigner {
        async fn sign_request(&self, _payload: &[u8]) -> Result<String, SignerError> {
            Err(SignerError::SigningFailed("kms unavailable".to_string()))
        }
    }

    #[tokio::test]
    async fn test_fordefi_custom_request_signer_sets_signature_header() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_test_signer_with(
            &mock_server.uri(),
            pubkey,
            Arc::new(CannedSigner("canned-sig-value")),
            None,
        );

        let message = b"custom signer message";
        let real_signature = keypair.sign_message(message);
        let sig_b64 = STANDARD.encode(real_signature.as_ref());

        // The POST must carry the exact x-signature produced by the custom signer.
        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("x-signature", "canned-sig-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "cs-1"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/cs-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "completed",
                "signatures": [{ "data": sig_b64 }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer.sign_message(message).await;
        assert!(
            result.is_ok(),
            "sign_message with custom signer failed: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), real_signature);
    }

    #[tokio::test]
    async fn test_fordefi_custom_request_signer_error_propagates() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer =
            create_test_signer_with(&mock_server.uri(), pubkey, Arc::new(FailingSigner), None);

        // Signing fails before any HTTP request is made, so no mock is needed.
        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[tokio::test]
    async fn test_fordefi_config_uses_custom_request_signer() {
        let mock_server = MockServer::start().await;
        let public_key = keypair_pubkey(&create_test_keypair());

        let mut config = verified_test_config(&mock_server.uri(), public_key);
        config.private_key_pem = None;
        config.request_signer = Some(Arc::new(CannedSigner("x")));

        Mock::given(method("GET"))
            .and(path("/api/v1/vaults/test-vault-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "address": public_key.to_string(),
                "id": "test-vault-id"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let signer = from_config_with_test_client(config).await.unwrap();
        assert_eq!(
            signer
                .sign_request("/api/v1/vaults", 123, "")
                .await
                .unwrap(),
            "x"
        );
    }

    #[test]
    fn test_fordefi_config_rejects_both_request_signing_mechanisms() {
        let public_key = keypair_pubkey(&create_test_keypair());
        let mut config = verified_test_config("https://api.test.fordefi.com", public_key);
        config.request_signer = Some(Arc::new(CannedSigner("x")));

        let result = FordefiSigner::build(config);

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_rejects_missing_request_signing_mechanism() {
        let public_key = keypair_pubkey(&create_test_keypair());
        let mut config = verified_test_config("https://api.test.fordefi.com", public_key);
        config.private_key_pem = None;

        let result = FordefiSigner::build(config);

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_custom_request_signer_still_validates_config() {
        let result = FordefiSigner::build(FordefiSignerConfig {
            access_token: String::new(),
            private_key_pem: None,
            request_signer: Some(Arc::new(CannedSigner("x"))),
            ..base_test_config()
        });

        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }
}
