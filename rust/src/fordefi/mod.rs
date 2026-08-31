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
    extract_api_error_with_transaction_id, parse_json_response, poll_until, read_body_capped,
    transaction_id_in_body, PollOutcome,
};
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{extract_and_verify_rewritten_transaction, signature_from_base64};
use crate::traits::{
    ModifyingSigner, SendingSigner, SignTransactionResult, SignedTransaction, SolanaSigner,
    TransactionSigner,
};
use crate::transaction_util::{
    idempotency_key_from_message, unconfirmed_unless_rejected, PendingTransactionId,
    TransactionUtil,
};
pub use request_signer::{FordefiRequestSigner, PemRequestSigner};
use types::{
    BlackBoxDetails, BlackBoxSignatureRequest, CreateTransactionResponse, SolanaMessageDetails,
    SolanaMessageRequest, SolanaTransactionDetails, SolanaTransactionRequest,
    TransactionStatusResponse, VaultResponse,
};
pub use types::{FordefiPriorityLevel, FordefiPushMode, FordefiSolanaFee, SolanaChainUniqueId};

const DEFAULT_BASE_URL: &str = "https://api.fordefi.com";
const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 50;
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Render a fee as `type|priority_level|unit_price|priority_fee`, with empty
/// segments for the fields the variant does not carry. The field order is fixed
/// so an idempotency key derived from it stays stable.
fn canonical_fee(fee: Option<&FordefiSolanaFee>) -> String {
    match fee {
        None => String::new(),
        Some(FordefiSolanaFee::Custom {
            unit_price,
            priority_fee,
        }) => format!(
            "custom||{}|{}",
            unit_price.as_deref().unwrap_or_default(),
            priority_fee.as_deref().unwrap_or_default()
        ),
        Some(FordefiSolanaFee::Priority { priority_level }) => {
            let level = match priority_level {
                FordefiPriorityLevel::Low => "low",
                FordefiPriorityLevel::Medium => "medium",
                FordefiPriorityLevel::High => "high",
            };
            format!("priority|{level}||")
        }
    }
}

/// Configuration for creating a Fordefi signer.
///
/// `chain` selects the signer type: `None` builds a [`FordefiBlackBoxSigner`].
/// With `chain` set, `push_mode` picks between [`FordefiNativeAutoSigner`]
/// ([`FordefiPushMode::Auto`] or `None`) and [`FordefiNativeManualSigner`]
/// ([`FordefiPushMode::Manual`]).
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
    /// Whether Fordefi broadcasts a native Solana transaction. `None` is
    /// equivalent to [`FordefiPushMode::Auto`]; [`FordefiPushMode::Manual`]
    /// requires `chain`.
    pub push_mode: Option<FordefiPushMode>,
}

/// Shared Fordefi API plumbing: request signing, submit, polling, vault lookup.
struct FordefiCore {
    access_token: String,
    vault_id: String,
    request_signer: Arc<dyn FordefiRequestSigner>,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
    poll_interval_ms: u64,
    max_poll_attempts: u32,
}

impl std::fmt::Debug for FordefiCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FordefiCore")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl FordefiCore {
    /// Validate the mode-independent config, resolve the request-signing
    /// mechanism, and assemble the core.
    ///
    /// `config.public_key` is trusted as the vault's Solana public key —
    /// construction makes no network calls, and every signature Fordefi
    /// returns is still verified against it.
    fn build(config: &FordefiSignerConfig) -> Result<Self, SignerError> {
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
            access_token: config.access_token.clone(),
            vault_id: config.vault_id.clone(),
            request_signer,
            api_base_url,
            client,
            public_key,
            poll_interval_ms,
            max_poll_attempts,
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
        let classify = |status: Option<u16>, provider_tx_id: Option<String>, error: SignerError| {
            if broadcast_managed {
                unconfirmed_unless_rejected(status, provider_tx_id, idempotence_id, error)
            } else {
                error
            }
        };

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|error| classify(None, None, error.into()))?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            let (error, provider_tx_id) =
                extract_api_error_with_transaction_id(response, "Fordefi API submit_request").await;
            return Err(classify(Some(status), provider_tx_id, error));
        }

        let body = read_body_capped(response)
            .await
            .map_err(|error| classify(Some(status), None, error))?;
        // The submit may have been accepted even when the body is otherwise
        // unusable, so an id present there is the caller's recovery handle.
        let provider_tx_id = transaction_id_in_body(&body);
        let create_response: CreateTransactionResponse = serde_json::from_slice(&body)
            .map_err(|error| classify(Some(status), provider_tx_id.clone(), error.into()))?;
        if create_response.id.is_empty() {
            return Err(classify(
                Some(status),
                provider_tx_id,
                SignerError::SerializationError(
                    "Fordefi API submit_request returned no transaction id".to_string(),
                ),
            ));
        }
        Ok(create_response.id)
    }

    /// Sign raw bytes via the black box path: submit → poll → extract signature.
    async fn sign_black_box(&self, data_bytes: &[u8]) -> Result<Signature, SignerError> {
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

        let tx_id = self.submit_request(&request, None, false).await?;
        self.poll_for_signature(&tx_id).await
    }

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
            || SignerError::RemoteApiError {
                detail: format!("Polling timeout after {} attempts", self.max_poll_attempts),
                provider_tx_id: Some(tx_id.to_string()),
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

    /// Submit a native Solana transaction request.
    ///
    /// The create carries an `x-idempotence-id` derived from the message bytes,
    /// so replaying these exact bytes cannot create a second transaction; a
    /// rebuilt transaction derives a different id. The key is namespaced by push
    /// mode, chain, vault and fee, so the same bytes submitted under any of them
    /// cannot collide with a create that carried different terms.
    async fn submit_solana_transaction(
        &self,
        chain: &SolanaChainUniqueId,
        fee: Option<&FordefiSolanaFee>,
        push_mode: FordefiPushMode,
        data_bytes: &[u8],
    ) -> Result<String, SignerError> {
        let request = SolanaTransactionRequest {
            vault_id: self.vault_id.clone(),
            signer_type: "api_signer",
            sign_mode: "auto",
            tx_type: "solana_transaction",
            details: SolanaTransactionDetails {
                detail_type: "solana_serialized_transaction_message",
                chain: chain.clone(),
                data: STANDARD.encode(data_bytes),
                push_mode,
                fee: fee.cloned(),
            },
        };

        let mode = match push_mode {
            FordefiPushMode::Auto => "auto",
            FordefiPushMode::Manual => "manual",
        };
        let mut namespaced = format!(
            "fordefi:solana:{}:{}:{}:{}:",
            mode,
            chain.as_str(),
            self.vault_id,
            canonical_fee(fee)
        )
        .into_bytes();
        namespaced.extend_from_slice(data_bytes);
        let idempotency_key = idempotency_key_from_message(&namespaced);

        self.submit_request(
            &request,
            Some(&idempotency_key),
            push_mode == FordefiPushMode::Auto,
        )
        .await
    }

    /// Submit a native Solana message request.
    async fn submit_solana_message(
        &self,
        chain: &SolanaChainUniqueId,
        message_bytes: &[u8],
    ) -> Result<String, SignerError> {
        let request = SolanaMessageRequest {
            vault_id: self.vault_id.clone(),
            signer_type: "api_signer",
            sign_mode: "auto",
            tx_type: "solana_message",
            details: SolanaMessageDetails {
                detail_type: "personal_message_type",
                chain: chain.clone(),
                raw_data: STANDARD.encode(message_bytes),
            },
        };

        self.submit_request(&request, None, false).await
    }

    /// Decode the base64 wire transaction a native poll response carries.
    fn decode_raw_transaction(result: &TransactionStatusResponse) -> Result<Vec<u8>, SignerError> {
        let raw_tx_b64 = result.raw_transaction.as_ref().ok_or_else(|| {
            SignerError::SigningFailed(
                "Fordefi solana_transaction response missing raw_transaction".to_string(),
            )
        })?;
        STANDARD.decode(raw_tx_b64).map_err(|e| {
            SignerError::SerializationError(format!("Failed to decode raw_transaction base64: {e}"))
        })
    }

    /// Verify `signature` against `message` with the vault's public key.
    fn verify_signature(&self, signature: &Signature, message: &[u8]) -> Result<(), SignerError> {
        if !signature.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed".to_string(),
            ));
        }
        Ok(())
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

/// Fordefi black-box signer: raw EdDSA signing via `black_box_signature`.
///
/// Signs the caller's transaction exactly as given; Fordefi does **not**
/// broadcast. The returned serialized transaction is the locally-assembled
/// signed tx, which the caller submits to an RPC.
pub struct FordefiBlackBoxSigner {
    core: FordefiCore,
}

impl std::fmt::Debug for FordefiBlackBoxSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FordefiBlackBoxSigner")
            .field("public_key", &self.core.public_key)
            .finish_non_exhaustive()
    }
}

impl FordefiBlackBoxSigner {
    /// Create a black-box signer from a configuration object.
    ///
    /// `config.chain`, `config.fee` and `config.push_mode` must be `None`; they
    /// belong to the native Solana signers.
    ///
    /// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    /// key in `config.private_key_pem`, or a custom [`FordefiRequestSigner`] in
    /// `config.request_signer` for KMS/HSM-backed signing.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        if config.chain.is_some() || config.fee.is_some() {
            return Err(SignerError::ConfigError(
                "chain and fee select native Solana mode; use FordefiNativeAutoSigner".to_string(),
            ));
        }
        if config.push_mode.is_some() {
            return Err(SignerError::ConfigError(
                "push_mode applies to native Solana mode only; it requires chain".to_string(),
            ));
        }
        Ok(Self {
            core: FordefiCore::build(&config)?,
        })
    }

    /// Sign a transaction via the black box path: submit → poll → apply signature.
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message.serialize();
        let signature = self.core.sign_black_box(&message_data).await?;
        self.core.verify_signature(&signature, &message_data)?;

        TransactionUtil::add_signature_to_transaction(
            transaction,
            &self.core.public_key,
            signature,
        )?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FordefiBlackBoxSigner {
    fn pubkey(&self) -> Pubkey {
        self.core.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let signature = self.core.sign_black_box(message).await?;
        self.core.verify_signature(&signature, message)?;
        Ok(signature)
    }

    async fn is_available(&self) -> bool {
        self.core.is_available().await
    }
}

#[async_trait::async_trait]
impl TransactionSigner for FordefiBlackBoxSigner {
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
}

/// Fordefi native Solana signer: `solana_transaction` / `solana_message` API
/// types with `push_mode: "auto"`.
///
/// Fordefi will modify the transaction (at minimum updating the blockhash, and
/// optionally adding priority fees) and **auto-broadcasts** it on-chain; the
/// returned signature is the on-chain identifier and the caller's transaction
/// is never mutated.
pub struct FordefiNativeAutoSigner {
    core: FordefiCore,
    chain: SolanaChainUniqueId,
    fee: Option<FordefiSolanaFee>,
    pending_transaction_id: Option<PendingTransactionId>,
}

impl std::fmt::Debug for FordefiNativeAutoSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FordefiNativeAutoSigner")
            .field("public_key", &self.core.public_key)
            .finish_non_exhaustive()
    }
}

impl FordefiNativeAutoSigner {
    /// Create a native auto-broadcast signer from a configuration object.
    ///
    /// `config.chain` must be set; leave it `None` for
    /// [`FordefiBlackBoxSigner`]. `config.push_mode` must be
    /// [`FordefiPushMode::Auto`] or `None`; [`FordefiPushMode::Manual`] belongs
    /// to [`FordefiNativeManualSigner`].
    ///
    /// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    /// key in `config.private_key_pem`, or a custom [`FordefiRequestSigner`] in
    /// `config.request_signer` for KMS/HSM-backed signing.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let Some(chain) = config.chain.clone() else {
            return Err(SignerError::ConfigError(
                "chain must be set for native Solana mode; use FordefiBlackBoxSigner without it"
                    .to_string(),
            ));
        };
        if config.push_mode == Some(FordefiPushMode::Manual) {
            return Err(SignerError::ConfigError(
                "manual push_mode does not broadcast; use FordefiNativeManualSigner".to_string(),
            ));
        }
        Ok(Self {
            core: FordefiCore::build(&config)?,
            chain,
            fee: config.fee,
            pending_transaction_id: None,
        })
    }

    /// Registers a slot for the provider id when cancellation prevents returning it.
    pub fn with_pending_transaction_id(mut self, pending: PendingTransactionId) -> Self {
        self.pending_transaction_id = Some(pending);
        self
    }

    /// Sign and broadcast via the native Solana path: submit → poll → parse wire tx.
    ///
    /// Fordefi will modify the transaction (at minimum updating the blockhash, and
    /// optionally adding priority fees), so we verify the signature against the
    /// returned message bytes, not the original. The caller's `transaction` is
    /// left untouched.
    ///
    /// A submit that fails without a usable response returns
    /// [`SignerError::BroadcastUnconfirmed`] with no transaction id.
    ///
    /// Each native create carries an `x-idempotence-id` derived from the message
    /// bytes, so replaying these exact bytes cannot create a second transaction; a
    /// rebuilt transaction derives a different id and is broadcast again.
    ///
    /// Cancelling this future returns nothing at all, so an accepted transaction
    /// id reaches the caller only through
    /// [`with_pending_transaction_id`](Self::with_pending_transaction_id).
    async fn sign_and_broadcast(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        self.validate_transaction(transaction)?;
        let message_data = transaction.message.serialize();
        let tx_id = self
            .core
            .submit_solana_transaction(
                &self.chain,
                self.fee.as_ref(),
                FordefiPushMode::Auto,
                &message_data,
            )
            .await?;
        // Once the submit is accepted Fordefi is already broadcasting
        // (push_mode: "auto"), so any later failure leaves an on-chain outcome
        // this client cannot rule out. Report those as BroadcastUnconfirmed
        // carrying the Fordefi transaction id instead of a generic error a
        // caller might blindly retry into a duplicate spend.
        // Cancelling this future runs no further code, so the registered slot is
        // the only way the accepted id reaches the caller in that case.
        if let Some(pending) = &self.pending_transaction_id {
            pending.set(&tx_id);
        }
        let result = self.finish_broadcast(&tx_id).await.map_err(|error| {
            SignerError::BroadcastUnconfirmed {
                provider_tx_id: Some(tx_id),
                provider_status: None,
                idempotency_key: None,
                detail: error.detail_string(),
            }
        });
        if let Some(pending) = &self.pending_transaction_id {
            pending.clear();
        }
        result
    }

    async fn finish_broadcast(&self, tx_id: &str) -> Result<Signature, SignerError> {
        let result = self.core.poll_for_result(tx_id, true).await?;
        let wire_bytes = FordefiCore::decode_raw_transaction(&result)?;
        let (_, signature) =
            extract_and_verify_rewritten_transaction(&wire_bytes, &self.core.public_key)?;
        Ok(signature)
    }

    /// Native auto-broadcast currently submits message bytes only. Transactions
    /// with additional required signers would also need their partial signatures
    /// forwarded through Fordefi's `details.signatures` request field.
    ///
    /// A signature already present can only be the vault's own over these bytes,
    /// which means they may already be on chain. Fordefi replaces the blockhash
    /// before broadcasting, so the result would be a second transaction carrying
    /// the same transfer, outside the network's replay protection.
    fn validate_transaction(&self, transaction: &VersionedTransaction) -> Result<(), SignerError> {
        let required_signatures = transaction.message.header().num_required_signatures as usize;
        if required_signatures != 1
            || transaction.message.static_account_keys().first() != Some(&self.core.public_key)
        {
            return Err(SignerError::SigningFailed(
                "Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault"
                    .to_string(),
            ));
        }
        if transaction
            .signatures
            .iter()
            .any(|signature| *signature != Signature::default())
        {
            return Err(SignerError::SigningFailed(
                "Fordefi native auto-broadcast must run before any transaction signatures are applied"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FordefiNativeAutoSigner {
    fn pubkey(&self) -> Pubkey {
        self.core.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let tx_id = self
            .core
            .submit_solana_message(&self.chain, message)
            .await?;
        let signature = self.core.poll_for_signature(&tx_id).await?;
        self.core.verify_signature(&signature, message)?;
        Ok(signature)
    }

    async fn is_available(&self) -> bool {
        self.core.is_available().await
    }
}

#[async_trait::async_trait]
impl SendingSigner for FordefiNativeAutoSigner {
    async fn sign_and_send_transaction(
        &self,
        tx: &VersionedTransaction,
    ) -> Result<Signature, SignerError> {
        self.sign_and_broadcast(tx).await
    }
}

/// Fordefi native Solana signer: `solana_transaction` API types with
/// `push_mode: "manual"`.
///
/// Fordefi rewrites the message (at minimum the recent blockhash, and it manages
/// the Compute Budget fee instructions), signs it and hands it back without
/// broadcasting. `modify_and_sign_transaction` replaces the caller's transaction
/// with the one the returned signature covers; the rewrite itself is not diffed,
/// so inspect the result before broadcasting.
///
/// Fordefi must be the fee payer, and it must sign before every downstream
/// signer: a transaction that already carries signatures is accepted, but the
/// rewrite voids them and the returned transaction carries only Fordefi's.
pub struct FordefiNativeManualSigner {
    core: FordefiCore,
    chain: SolanaChainUniqueId,
    fee: Option<FordefiSolanaFee>,
}

impl std::fmt::Debug for FordefiNativeManualSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FordefiNativeManualSigner")
            .field("public_key", &self.core.public_key)
            .finish_non_exhaustive()
    }
}

impl FordefiNativeManualSigner {
    /// Create a native signer that does not broadcast, from a configuration
    /// object.
    ///
    /// `config.chain` must be set and `config.push_mode` must be
    /// [`FordefiPushMode::Manual`]; anything else belongs to
    /// [`FordefiBlackBoxSigner`] or [`FordefiNativeAutoSigner`].
    ///
    /// Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    /// key in `config.private_key_pem`, or a custom [`FordefiRequestSigner`] in
    /// `config.request_signer` for KMS/HSM-backed signing.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let Some(chain) = config.chain.clone() else {
            return Err(SignerError::ConfigError(
                "manual push_mode requires chain to be set (native Solana mode)".to_string(),
            ));
        };
        if config.push_mode != Some(FordefiPushMode::Manual) {
            return Err(SignerError::ConfigError(
                "manual push_mode must be set explicitly; use FordefiNativeAutoSigner to broadcast"
                    .to_string(),
            ));
        }
        Ok(Self {
            core: FordefiCore::build(&config)?,
            chain,
            fee: config.fee,
        })
    }

    /// Rewrite and sign via the native Solana path: submit → poll → parse wire tx.
    ///
    /// `transaction` is replaced with the bytes the returned signature covers.
    async fn modify_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.validate_transaction(transaction)?;
        let message_data = transaction.message.serialize();
        let tx_id = self
            .core
            .submit_solana_transaction(
                &self.chain,
                self.fee.as_ref(),
                FordefiPushMode::Manual,
                &message_data,
            )
            .await?;

        let result = self.core.poll_for_result(&tx_id, false).await?;
        let wire_bytes = FordefiCore::decode_raw_transaction(&result)?;
        let (returned_tx, signature) =
            extract_and_verify_rewritten_transaction(&wire_bytes, &self.core.public_key)?;

        let encoded = TransactionUtil::serialize_transaction(&returned_tx)?;
        *transaction = returned_tx;
        Ok((encoded, signature))
    }

    /// Fordefi only rewrites a message it pays for.
    fn validate_transaction(&self, transaction: &VersionedTransaction) -> Result<(), SignerError> {
        if transaction.message.static_account_keys().first() != Some(&self.core.public_key) {
            return Err(SignerError::SigningFailed(
                "Fordefi native manual signing requires the configured vault to be the transaction fee payer"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl SolanaSigner for FordefiNativeManualSigner {
    fn pubkey(&self) -> Pubkey {
        self.core.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let tx_id = self
            .core
            .submit_solana_message(&self.chain, message)
            .await?;
        let signature = self.core.poll_for_signature(&tx_id).await?;
        self.core.verify_signature(&signature, message)?;
        Ok(signature)
    }

    async fn is_available(&self) -> bool {
        self.core.is_available().await
    }
}

#[async_trait::async_trait]
impl ModifyingSigner for FordefiNativeManualSigner {
    async fn modify_and_sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.modify_and_serialize(tx).await?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }
}

#[cfg(test)]
mod tests;
