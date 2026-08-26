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
use crate::remote_util::{
    extract_api_error, parse_json_response, poll_until, read_body_capped, PollOutcome,
};
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::signature_from_base64;
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner};
use crate::transaction_util::{
    deserialize_wire_transaction, idempotency_key_from_message, unconfirmed_unless_rejected,
    TransactionUtil,
};
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
/// Supports two signing modes, which differ in which entry point is available:
/// - **Black box** (default, `chain` = `None`): Signs raw bytes via `black_box_signature`
///   through `sign_transaction`. Fordefi does **not** broadcast; the returned serialized
///   transaction is the locally-assembled signed tx, which the caller submits to an RPC.
///   `sign_and_send_transaction` is rejected in this mode.
/// - **Native Solana** (`chain` = `Some(...)`): Uses `solana_transaction` / `solana_message`
///   API types through `sign_and_send_transaction`. Fordefi will modify the transaction
///   (at minimum updating the blockhash, and optionally adding priority fees),
///   **auto-broadcasts** it on-chain (`push_mode: "auto"`), and returns the signature,
///   the on-chain identifier. `sign_transaction` is rejected in this mode.
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
    /// `config.public_key` is trusted as the vault's Solana public key —
    /// construction makes no network calls, and every signature Fordefi
    /// returns is still verified against it.
    ///
    /// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    /// key in `config.private_key_pem`, or a custom [`FordefiRequestSigner`] in
    /// `config.request_signer` for KMS/HSM-backed signing.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        Self::build(config)
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
    /// `broadcast_managed` marks a submit whose acceptance means Fordefi is already
    /// broadcasting, so an unresolved failure is reported as unconfirmed.
    async fn submit_request<T: serde::Serialize>(
        &self,
        request: &T,
        idempotence_id: Option<&str>,
        broadcast_managed: bool,
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
        let classify = |status: Option<u16>, error: SignerError| {
            if broadcast_managed {
                unconfirmed_unless_rejected(status, error)
            } else {
                error
            }
        };

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|error| classify(None, error.into()))?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let error = extract_api_error(response, "Fordefi API submit_request").await;
            return Err(classify(Some(status), error));
        }

        let body = read_body_capped(response)
            .await
            .map_err(|error| classify(Some(status), error))?;
        let create_response: CreateTransactionResponse =
            serde_json::from_slice(&body).map_err(|error| classify(Some(status), error.into()))?;
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

        self.submit_request(&request, None, false).await
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
            Some(&idempotency_key_from_message(data_bytes)),
            true,
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

        self.submit_request(&request, None, false).await
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
        let url = format!("{}/api/v1/transactions/{}", self.api_base_url, tx_id);
        poll_until(
            self.max_poll_attempts,
            self.poll_interval_ms,
            || {
                SignerError::RemoteApiError(format!(
                    "Polling timeout after {} attempts",
                    self.max_poll_attempts
                ))
            },
            || async {
                let response = self
                    .client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", self.access_token))
                    .send()
                    .await?;

                let tx_data: TransactionStatusResponse =
                    parse_json_response(response, "Fordefi API poll_result").await?;

                let is_success = if pushable {
                    matches!(tx_data.state.as_str(), "completed")
                } else {
                    matches!(tx_data.state.as_str(), "signed" | "completed")
                };

                if is_success {
                    return Ok(PollOutcome::Done(tx_data));
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

                Ok(PollOutcome::Pending)
            },
        )
        .await
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

        signature_from_base64(&entry.data)
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
    /// A submit that fails without a usable response returns
    /// [`SignerError::BroadcastUnconfirmed`] with no transaction id.
    ///
    /// Each native create carries an `x-idempotence-id` derived from the message
    /// bytes, so replaying these exact bytes cannot create a second transaction; a
    /// rebuilt transaction derives a different id and is broadcast again.
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
                provider_tx_id: Some(tx_id),
                provider_status: None,
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

        let returned_tx: VersionedTransaction =
            deserialize_wire_transaction(&wire_bytes).map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to deserialize Fordefi wire transaction: {e}"
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

    /// Fetch the configured vault from Fordefi.
    async fn fetch_vault(&self) -> Result<VaultResponse, SignerError> {
        let url = format!("{}/api/v1/vaults/{}", self.api_base_url, self.vault_id);
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;

        parse_json_response(response, "Fordefi API fetch_vault").await
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
        if self.chain.is_some() {
            return Err(SignerError::SigningFailed(
                "Fordefi native mode broadcasts through its own API; call \
                 sign_and_send_transaction instead"
                    .to_string(),
            ));
        }
        let signed_transaction = self.sign_and_serialize_black_box(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }

    async fn sign_and_send_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        if self.chain.is_none() {
            return Err(SignerError::SigningFailed(
                "Fordefi black-box mode only signs; sign the transaction and broadcast the result"
                    .to_string(),
            ));
        }
        let (_, signature) = self.sign_and_serialize_native(tx).await?;
        Ok(signature)
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
mod tests;
