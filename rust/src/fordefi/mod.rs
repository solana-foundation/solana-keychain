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
use crate::sdk_adapter::{
    CompiledInstruction, MessageHeader, Pubkey, Signature, VersionedMessage, VersionedTransaction,
    COMPUTE_BUDGET_PROGRAM_ID,
};
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner};
use crate::transaction_util::{
    deserialize_wire_transaction, idempotency_key_from_message, serialize_wire_transaction,
    unconfirmed_unless_rejected, TransactionUtil,
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
const VAULT_VERIFICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const SOLANA_PACKET_DATA_SIZE: usize = 1232;
const SET_COMPUTE_UNIT_LIMIT: u8 = 2;
const SET_COMPUTE_UNIT_PRICE: u8 = 3;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
const MICRO_LAMPORTS_PER_LAMPORT: u128 = 1_000_000;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ManualFeeInstructions {
    limit: Option<u32>,
    price: Option<u64>,
}

fn compare_manual_messages_exactly(
    original: &VersionedMessage,
    returned: &VersionedMessage,
    allow_blockhash_replacement: bool,
) -> Result<(), SignerError> {
    let mut comparable = returned.clone();
    if allow_blockhash_replacement {
        comparable.set_recent_blockhash(*original.recent_blockhash());
    }
    if comparable.serialize() != original.serialize() {
        return Err(SignerError::SigningFailed(
            "Fordefi manual signing changed transaction content outside the permitted recent blockhash"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_manual_fee_message(
    message: &VersionedMessage,
) -> Result<(VersionedMessage, ManualFeeInstructions), SignerError> {
    let mut normalized = message.clone();
    let fees = match &mut normalized {
        VersionedMessage::Legacy(message) => normalize_manual_fee_components(
            &mut message.header,
            &mut message.account_keys,
            &mut message.instructions,
        )?,
        VersionedMessage::V0(message) => normalize_manual_fee_components(
            &mut message.header,
            &mut message.account_keys,
            &mut message.instructions,
        )?,
        #[cfg(feature = "sdk-v4")]
        VersionedMessage::V1(_) => {
            return Err(SignerError::SigningFailed(
                "Fordefi manual v1 transactions may only replace the recent blockhash".to_string(),
            ));
        }
    };
    Ok((normalized, fees))
}

fn normalize_manual_fee_components(
    header: &mut MessageHeader,
    account_keys: &mut Vec<Pubkey>,
    instructions: &mut Vec<CompiledInstruction>,
) -> Result<ManualFeeInstructions, SignerError> {
    let compute_budget_id = COMPUTE_BUDGET_PROGRAM_ID;
    let mut fees = ManualFeeInstructions::default();
    let mut retained = Vec::with_capacity(instructions.len());

    for instruction in instructions.drain(..) {
        let program_id = account_keys.get(instruction.program_id_index as usize);
        if program_id != Some(&compute_budget_id)
            || !matches!(
                instruction.data.first().copied(),
                Some(SET_COMPUTE_UNIT_LIMIT) | Some(SET_COMPUTE_UNIT_PRICE)
            )
        {
            retained.push(instruction);
            continue;
        }
        if !instruction.accounts.is_empty() {
            return Err(SignerError::SigningFailed(
                "Fordefi returned an account-bearing Compute Budget fee instruction".to_string(),
            ));
        }
        match instruction.data.first().copied() {
            Some(SET_COMPUTE_UNIT_LIMIT) => {
                if instruction.data.len() != 5 || fees.limit.is_some() {
                    return Err(SignerError::SigningFailed(
                        "Fordefi returned a malformed or duplicate compute-unit limit".to_string(),
                    ));
                }
                let value =
                    u32::from_le_bytes(instruction.data[1..5].try_into().map_err(|_| {
                        SignerError::SigningFailed(
                            "Fordefi returned a malformed compute-unit limit".to_string(),
                        )
                    })?);
                if value == 0 || value > MAX_COMPUTE_UNIT_LIMIT {
                    return Err(SignerError::SigningFailed(
                        "Fordefi returned an out-of-range compute-unit limit".to_string(),
                    ));
                }
                fees.limit = Some(value);
            }
            Some(SET_COMPUTE_UNIT_PRICE) => {
                if instruction.data.len() != 9 || fees.price.is_some() {
                    return Err(SignerError::SigningFailed(
                        "Fordefi returned a malformed or duplicate compute-unit price".to_string(),
                    ));
                }
                fees.price = Some(u64::from_le_bytes(
                    instruction.data[1..9].try_into().map_err(|_| {
                        SignerError::SigningFailed(
                            "Fordefi returned a malformed compute-unit price".to_string(),
                        )
                    })?,
                ));
            }
            _ => unreachable!(),
        }
    }
    *instructions = retained;
    prune_unused_compute_budget_key(header, account_keys, instructions, &compute_budget_id)?;
    Ok(fees)
}

fn prune_unused_compute_budget_key(
    header: &mut MessageHeader,
    account_keys: &mut Vec<Pubkey>,
    instructions: &mut [CompiledInstruction],
    compute_budget_id: &Pubkey,
) -> Result<(), SignerError> {
    let positions: Vec<usize> = account_keys
        .iter()
        .enumerate()
        .filter_map(|(index, key)| (key == compute_budget_id).then_some(index))
        .collect();
    if positions.len() != 1 {
        return Ok(());
    }
    let index = positions[0];
    let unsigned_readonly_start = account_keys
        .len()
        .checked_sub(header.num_readonly_unsigned_accounts as usize)
        .ok_or_else(|| {
            SignerError::SigningFailed("Invalid transaction message header".to_string())
        })?;
    if index < header.num_required_signatures as usize || index < unsigned_readonly_start {
        return Ok(());
    }
    let referenced = instructions.iter().any(|instruction| {
        instruction.program_id_index as usize == index
            || instruction
                .accounts
                .iter()
                .any(|account| *account as usize == index)
    });
    if referenced {
        return Ok(());
    }

    account_keys.remove(index);
    header.num_readonly_unsigned_accounts = header
        .num_readonly_unsigned_accounts
        .checked_sub(1)
        .ok_or_else(|| {
            SignerError::SigningFailed("Invalid transaction message header".to_string())
        })?;
    for instruction in instructions {
        if instruction.program_id_index as usize > index {
            instruction.program_id_index =
                instruction.program_id_index.checked_sub(1).ok_or_else(|| {
                    SignerError::SigningFailed("Invalid compiled instruction index".to_string())
                })?;
        }
        for account in &mut instruction.accounts {
            if *account as usize > index {
                *account = account.checked_sub(1).ok_or_else(|| {
                    SignerError::SigningFailed("Invalid compiled account index".to_string())
                })?;
            }
        }
    }
    Ok(())
}

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
/// Supports three signing modes, which differ in what `sign_transaction` returns:
/// - **Black box** (default, `chain` = `None`): Signs raw bytes via `black_box_signature`
///   and returns nothing else. Fordefi does **not** broadcast; the returned serialized
///   transaction is the locally-assembled signed tx, which the caller submits to an RPC.
/// - **Native auto** (`chain` = `Some(...)`, `push_mode` = `Auto`): Uses `solana_transaction` / `solana_message`
///   API types. Fordefi will modify the transaction (at minimum updating the blockhash,
///   and optionally adding priority fees) and **auto-broadcasts** it on-chain
///   (`push_mode: "auto"`). Because the transaction is already submitted, the returned
///   serialized transaction is **empty** — only the signature, the on-chain
///   identifier, is returned. The caller's `&mut Transaction` is left untouched.
/// - **Native manual** (`chain` = `Some(...)`, `push_mode` = `Manual`): for the
///   unsigned requests supported here, Fordefi may replace the blockhash and
///   manage priority-fee instructions without broadcasting. The caller's
///   transaction is replaced only after all other content is validated.
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
    push_mode: FordefiPushMode,
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

    /// Create a FordefiSigner with an explicit native transaction push mode.
    ///
    /// `Manual` requires `config.chain` and returns validated blockhash/fee-
    /// updated signed transactions without broadcasting them. `Auto` preserves
    /// the behavior of [`Self::from_config`].
    pub async fn from_config_with_push_mode(
        config: FordefiSignerConfig,
        push_mode: FordefiPushMode,
    ) -> Result<Self, SignerError> {
        let signer = Self::build_with_push_mode(config, push_mode)?;
        signer.verify_vault_address_with_timeout().await?;
        Ok(signer)
    }

    /// Shared construction: validate config, resolve the request-signing
    /// mechanism, and assemble the signer.
    fn build(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        Self::build_with_push_mode(config, FordefiPushMode::Auto)
    }

    fn build_with_push_mode(
        config: FordefiSignerConfig,
        push_mode: FordefiPushMode,
    ) -> Result<Self, SignerError> {
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

        if push_mode == FordefiPushMode::Manual && config.chain.is_none() {
            return Err(SignerError::ConfigError(
                "manual push mode requires chain to be set (native Solana mode)".to_string(),
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
            push_mode,
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
            let error = Self::extract_api_error(response, "submit_request").await;
            return Err(classify(Some(status), error));
        }

        let create_response: CreateTransactionResponse = response
            .json()
            .await
            .map_err(|error| classify(Some(status), error.into()))?;
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
                push_mode: self.push_mode,
                fee: self.fee.clone(),
            },
        };

        let idempotence_id = match self.push_mode {
            FordefiPushMode::Auto => idempotency_key_from_message(data_bytes),
            FordefiPushMode::Manual => {
                let mut namespaced = format!(
                    "fordefi:solana:manual:{}:{}:",
                    chain.as_str(),
                    self.vault_id
                )
                .into_bytes();
                namespaced.extend_from_slice(data_bytes);
                idempotency_key_from_message(&namespaced)
            }
        };

        self.submit_request(
            &request,
            Some(&idempotence_id),
            self.push_mode == FordefiPushMode::Auto,
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
    /// false (black box / messages / native manual), the terminal success state is `signed`
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
    /// A submit that fails without a usable response returns
    /// [`SignerError::BroadcastUnconfirmed`] with no transaction id.
    ///
    /// Each native create carries an `x-idempotence-id` derived from the message
    /// bytes, so replaying these exact bytes cannot create a second transaction; a
    /// rebuilt transaction derives a different id and is broadcast again.
    async fn sign_and_serialize_native_auto(
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

    /// Sign through Fordefi's native Solana path without broadcasting.
    async fn sign_and_serialize_native_manual(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.validate_native_manual_transaction(transaction)?;
        let message_data = transaction.message.serialize();
        let tx_id = self.submit_solana_transaction(&message_data).await?;
        let (returned_tx, signature) = self.finish_native_manual(&tx_id, transaction).await?;

        let canonical_wire = serialize_wire_transaction(&returned_tx)?;
        if canonical_wire.len() > SOLANA_PACKET_DATA_SIZE {
            return Err(SignerError::SigningFailed(format!(
                "Fordefi manual wire transaction exceeds the Solana size limit: {} > {} bytes",
                canonical_wire.len(),
                SOLANA_PACKET_DATA_SIZE
            )));
        }
        let serialized_transaction = STANDARD.encode(canonical_wire);

        // Do not mutate caller-owned state until every remote response check and
        // local serialization step has succeeded.
        *transaction = returned_tx;
        Ok((serialized_transaction, signature))
    }

    fn validate_manual_message_mutation(
        &self,
        original_tx: &VersionedTransaction,
        returned_tx: &VersionedTransaction,
    ) -> Result<(), SignerError> {
        if std::mem::discriminant(&original_tx.message)
            != std::mem::discriminant(&returned_tx.message)
        {
            return Err(SignerError::SigningFailed(
                "Fordefi manual signing changed the transaction message version".to_string(),
            ));
        }

        if original_tx.uses_durable_nonce() {
            compare_manual_messages_exactly(&original_tx.message, &returned_tx.message, false)?;
            #[cfg(feature = "sdk-v4")]
            if matches!(&original_tx.message, VersionedMessage::V1(_)) {
                return Ok(());
            }
            let (_, original_fee) = normalize_manual_fee_message(&original_tx.message)?;
            return self.validate_manual_custom_fee(original_fee);
        }

        #[cfg(feature = "sdk-v4")]
        if matches!(&original_tx.message, VersionedMessage::V1(_)) {
            return compare_manual_messages_exactly(
                &original_tx.message,
                &returned_tx.message,
                true,
            );
        }

        let (normalized_original, original_fee) =
            normalize_manual_fee_message(&original_tx.message)?;
        if original_fee.price.is_some() {
            compare_manual_messages_exactly(&original_tx.message, &returned_tx.message, true)?;
            return self.validate_manual_custom_fee(original_fee);
        }

        let (mut normalized_returned, returned_fee) =
            normalize_manual_fee_message(&returned_tx.message)?;
        self.validate_manual_custom_fee(returned_fee)?;
        normalized_returned.set_recent_blockhash(*normalized_original.recent_blockhash());
        if normalized_returned.serialize() != normalized_original.serialize() {
            return Err(SignerError::SigningFailed(
                "Fordefi manual signing changed transaction content outside the recent blockhash and priority fee"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_manual_custom_fee(
        &self,
        returned_fee: ManualFeeInstructions,
    ) -> Result<(), SignerError> {
        let Some(FordefiSolanaFee::Custom {
            unit_price,
            priority_fee,
        }) = &self.fee
        else {
            return Ok(());
        };
        if let Some(configured) = unit_price {
            let expected = configured.parse::<u64>().map_err(|_| {
                SignerError::SigningFailed("Configured custom unit_price is invalid".to_string())
            })?;
            if returned_fee.price != Some(expected) {
                return Err(SignerError::SigningFailed(
                    "Fordefi returned a compute-unit price that does not match the configured custom unit_price"
                        .to_string(),
                ));
            }
        }
        if let (Some(configured), Some(returned_price)) = (priority_fee, returned_fee.price) {
            let maximum = configured.parse::<u128>().map_err(|_| {
                SignerError::SigningFailed("Configured custom priority_fee is invalid".to_string())
            })?;
            let limit = returned_fee.limit.unwrap_or(MAX_COMPUTE_UNIT_LIMIT) as u128;
            let effective = ((returned_price as u128) * limit)
                .saturating_add(MICRO_LAMPORTS_PER_LAMPORT - 1)
                / MICRO_LAMPORTS_PER_LAMPORT;
            if effective > maximum {
                return Err(SignerError::SigningFailed(
                    "Fordefi returned a priority fee above the configured custom priority_fee"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Decode and validate the transaction returned by native manual signing.
    async fn finish_native_manual(
        &self,
        tx_id: &str,
        original_tx: &VersionedTransaction,
    ) -> Result<(VersionedTransaction, Signature), SignerError> {
        let result = self.poll_for_result(tx_id, false).await?;
        let raw_tx_b64 = result.raw_transaction.as_ref().ok_or_else(|| {
            SignerError::SigningFailed(
                "Fordefi manual solana_transaction response missing raw_transaction".to_string(),
            )
        })?;

        let wire_bytes = STANDARD.decode(raw_tx_b64).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to decode Fordefi manual raw_transaction base64: {e}"
            ))
        })?;
        if wire_bytes.len() > SOLANA_PACKET_DATA_SIZE {
            return Err(SignerError::SigningFailed(format!(
                "Fordefi manual wire transaction exceeds the Solana size limit: {} > {} bytes",
                wire_bytes.len(),
                SOLANA_PACKET_DATA_SIZE
            )));
        }

        let returned_tx = deserialize_wire_transaction(&wire_bytes).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to deserialize Fordefi manual wire transaction: {e}"
            ))
        })?;

        let original_signers = Self::required_signer_keys(original_tx)?;
        let returned_signers = Self::required_signer_keys(&returned_tx)?;
        if original_signers != returned_signers {
            return Err(SignerError::SigningFailed(
                "Fordefi manual signing changed the transaction required-signer set".to_string(),
            ));
        }

        self.validate_manual_message_mutation(original_tx, &returned_tx)?;
        if returned_tx.signatures.len() != returned_signers.len() {
            return Err(SignerError::SigningFailed(
                "Fordefi manual wire transaction has an invalid signature-slot count".to_string(),
            ));
        }

        let signature = self.extract_vault_signature(&returned_tx)?;
        if signature == Signature::default() {
            return Err(SignerError::SigningFailed(
                "Fordefi manual wire transaction did not contain the configured vault signature"
                    .to_string(),
            ));
        }
        if returned_tx
            .signatures
            .iter()
            .skip(1)
            .any(|signature| *signature != Signature::default())
        {
            return Err(SignerError::SigningFailed(
                "Fordefi manual signing unexpectedly populated a downstream signer slot"
                    .to_string(),
            ));
        }

        let returned_message = returned_tx.message.serialize();
        if !signature.verify(&self.public_key.to_bytes(), &returned_message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed against Fordefi-returned manual message".to_string(),
            ));
        }

        Ok((returned_tx, signature))
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

    /// Native manual signing must run first, with Fordefi as the fee payer.
    fn validate_native_manual_transaction(
        &self,
        transaction: &VersionedTransaction,
    ) -> Result<(), SignerError> {
        let required_signers = Self::required_signer_keys(transaction)?;
        if required_signers.first() != Some(&self.public_key) {
            return Err(SignerError::SigningFailed(
                "Fordefi native manual signing requires the configured vault to be the transaction fee payer"
                    .to_string(),
            ));
        }
        if transaction
            .signatures
            .iter()
            .any(|signature| *signature != Signature::default())
        {
            return Err(SignerError::SigningFailed(
                "Fordefi native manual signing must run before any transaction signatures are applied"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn required_signer_keys(transaction: &VersionedTransaction) -> Result<&[Pubkey], SignerError> {
        let required_signatures = transaction.message.header().num_required_signatures as usize;
        transaction
            .message
            .static_account_keys()
            .get(..required_signatures)
            .ok_or_else(|| {
                SignerError::SigningFailed(
                    "Transaction does not contain all required signer account keys".to_string(),
                )
            })
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
        match (self.chain.is_some(), self.push_mode) {
            (true, FordefiPushMode::Auto) => self.sign_and_serialize_native_auto(transaction).await,
            (true, FordefiPushMode::Manual) => {
                self.sign_and_serialize_native_manual(transaction).await
            }
            (false, _) => self.sign_and_serialize_black_box(transaction).await,
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
        self.chain.is_some() && self.push_mode == FordefiPushMode::Auto
    }

    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let signed_transaction = self.sign_and_serialize(tx).await?;
        if self.broadcasts_transactions() {
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
    use crate::sdk_adapter::{
        keypair_pubkey, Hash, Keypair, Signer as SdkSigner, VersionedMessage,
    };
    #[cfg(feature = "sdk-v4")]
    use crate::test_util::create_test_v1_transaction;
    use crate::test_util::{
        add_required_signer, create_test_transaction, create_test_v0_transaction,
    };
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
        create_test_signer_with_mode(
            base_url,
            pubkey,
            request_signer,
            chain,
            FordefiPushMode::Auto,
        )
    }

    fn create_test_signer_with_mode(
        base_url: &str,
        pubkey: Pubkey,
        request_signer: Arc<dyn FordefiRequestSigner>,
        chain: Option<SolanaChainUniqueId>,
        push_mode: FordefiPushMode,
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
            push_mode,
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

    fn create_native_manual_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
        create_test_signer_with_mode(
            base_url,
            pubkey,
            test_request_signer(),
            Some(SolanaChainUniqueId::SolanaMainnet),
            FordefiPushMode::Manual,
        )
    }

    #[test]
    fn test_broadcasts_transactions_by_mode() {
        let pubkey = Pubkey::new_unique();
        assert!(!create_test_signer("https://example.com", pubkey).broadcasts_transactions());
        assert!(create_native_test_signer("https://example.com", pubkey).broadcasts_transactions());
        assert!(
            !create_native_manual_test_signer("https://example.com", pubkey)
                .broadcasts_transactions()
        );
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

    fn signed_wire_transaction(
        transaction: &mut VersionedTransaction,
        keypair: &Keypair,
    ) -> (Vec<u8>, Signature) {
        let message_bytes = transaction.message.serialize();
        let signature = keypair.sign_message(&message_bytes);
        let required_signatures = transaction.message.header().num_required_signatures as usize;
        transaction
            .signatures
            .resize(required_signatures, Signature::default());
        transaction.signatures[0] = signature;
        (
            serialize_wire_transaction(transaction).expect("serialize signed transaction"),
            signature,
        )
    }

    fn prepend_manual_compute_budget_instruction(
        transaction: &mut VersionedTransaction,
        data: Vec<u8>,
        accounts: Vec<u8>,
    ) {
        let compute_budget_id = COMPUTE_BUDGET_PROGRAM_ID;
        let (header, account_keys, instructions) = match &mut transaction.message {
            VersionedMessage::Legacy(message) => (
                &mut message.header,
                &mut message.account_keys,
                &mut message.instructions,
            ),
            VersionedMessage::V0(message) => (
                &mut message.header,
                &mut message.account_keys,
                &mut message.instructions,
            ),
            #[cfg(feature = "sdk-v4")]
            VersionedMessage::V1(_) => panic!("fee helper does not support v1"),
        };
        let program_id_index = account_keys
            .iter()
            .position(|key| key == &compute_budget_id)
            .unwrap_or_else(|| {
                let index = account_keys.len();
                account_keys.push(compute_budget_id);
                header.num_readonly_unsigned_accounts += 1;
                index
            });
        instructions.insert(
            0,
            CompiledInstruction {
                program_id_index: u8::try_from(program_id_index).unwrap(),
                accounts,
                data,
            },
        );
    }

    fn compute_limit_data(limit: u32) -> Vec<u8> {
        let mut data = vec![SET_COMPUTE_UNIT_LIMIT];
        data.extend_from_slice(&limit.to_le_bytes());
        data
    }

    fn compute_price_data(price: u64) -> Vec<u8> {
        let mut data = vec![SET_COMPUTE_UNIT_PRICE];
        data.extend_from_slice(&price.to_le_bytes());
        data
    }

    async fn assert_native_manual_round_trip(
        mut transaction: VersionedTransaction,
        keypair: &Keypair,
        terminal_state: &str,
    ) {
        let mock_server = MockServer::start().await;
        let pubkey = keypair_pubkey(keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let original_message = transaction.message.serialize();

        let mut returned_tx = transaction.clone();
        returned_tx.message.set_recent_blockhash(Hash::new_unique());
        let returned_message = returned_tx.message.serialize();
        let (wire_bytes, expected_signature) = signed_wire_transaction(&mut returned_tx, keypair);
        let wire_b64 = STANDARD.encode(wire_bytes);

        let mut idempotency_input = b"fordefi:solana:manual:solana_mainnet:test-vault-id:".to_vec();
        idempotency_input.extend_from_slice(&original_message);
        let expected_idempotence_id = idempotency_key_from_message(&idempotency_input);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("x-idempotence-id", expected_idempotence_id.as_str()))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "type": "solana_transaction",
                "details": {
                    "type": "solana_serialized_transaction_message",
                    "push_mode": "manual"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "native-manual-tx"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/native-manual-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": terminal_state,
                "raw_transaction": wire_b64
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = signer
            .sign_transaction(&mut transaction)
            .await
            .expect("manual transaction should sign");
        assert!(matches!(result, SignTransactionResult::Complete(_)));
        let (serialized_transaction, signature) = result.into_signed_transaction();
        assert!(!serialized_transaction.is_empty());
        assert_eq!(signature, expected_signature);
        assert!(signature.verify(&pubkey.to_bytes(), &returned_message));
        assert_ne!(original_message, returned_message);
        assert_eq!(transaction.message.serialize(), returned_message);
        assert_eq!(transaction.signatures, returned_tx.signatures);

        let decoded = deserialize_wire_transaction(
            &STANDARD
                .decode(serialized_transaction)
                .expect("decode returned base64 transaction"),
        )
        .expect("decode returned wire transaction");
        assert_eq!(decoded.message.serialize(), transaction.message.serialize());
        assert_eq!(decoded.signatures, transaction.signatures);
    }

    async fn mount_native_manual_result(
        mock_server: &MockServer,
        tx_id: &str,
        state: &str,
        raw_transaction: Option<String>,
    ) {
        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": tx_id
            })))
            .expect(1)
            .mount(mock_server)
            .await;

        let mut poll_body = serde_json::json!({ "state": state });
        if let Some(raw_transaction) = raw_transaction {
            poll_body["raw_transaction"] = serde_json::Value::String(raw_transaction);
        }
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/transactions/{tx_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(poll_body))
            .expect(1)
            .mount(mock_server)
            .await;
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
    fn test_fordefi_manual_config_requires_chain() {
        let result =
            FordefiSigner::build_with_push_mode(base_test_config(), FordefiPushMode::Manual);
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_manual_config_with_chain_valid() {
        let result = FordefiSigner::build_with_push_mode(
            FordefiSignerConfig {
                chain: Some(SolanaChainUniqueId::SolanaDevnet),
                ..base_test_config()
            },
            FordefiPushMode::Manual,
        );
        assert_eq!(result.unwrap().push_mode, FordefiPushMode::Manual);
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
        add_required_signer(&mut returned_tx, fordefi_pubkey);
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
        add_required_signer(&mut tx, fordefi_pubkey);

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

        let expected_idempotence_id = idempotency_key_from_message(&message_data);
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
    async fn test_fordefi_native_manual_replaces_legacy_transaction() {
        let keypair = create_test_keypair();
        let transaction = create_test_transaction(&keypair_pubkey(&keypair));
        assert_native_manual_round_trip(transaction, &keypair, "signed").await;
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_replaces_v0_transaction() {
        let keypair = create_test_keypair();
        let transaction = create_test_v0_transaction(&keypair_pubkey(&keypair));
        assert_native_manual_round_trip(transaction, &keypair, "completed").await;
    }

    #[test]
    fn test_fordefi_native_manual_message_mutation_fee_policy() {
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let base = create_test_v0_transaction(&pubkey);
        let signer = create_native_manual_test_signer("https://example.com", pubkey);

        let mut returned = base.clone();
        returned.message.set_recent_blockhash(Hash::new_unique());
        prepend_manual_compute_budget_instruction(
            &mut returned,
            compute_limit_data(300_000),
            vec![],
        );
        prepend_manual_compute_budget_instruction(&mut returned, compute_price_data(7), vec![]);
        signer
            .validate_manual_message_mutation(&base, &returned)
            .unwrap();

        let mut original_limit = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut original_limit,
            compute_limit_data(200_000),
            vec![],
        );
        let mut adjusted_limit = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut adjusted_limit,
            compute_limit_data(400_000),
            vec![],
        );
        signer
            .validate_manual_message_mutation(&original_limit, &adjusted_limit)
            .unwrap();
        signer
            .validate_manual_message_mutation(&original_limit, &base)
            .unwrap();

        let mut heap = base.clone();
        prepend_manual_compute_budget_instruction(&mut heap, vec![1, 0, 128, 0, 0], vec![]);
        let mut heap_with_price = heap.clone();
        prepend_manual_compute_budget_instruction(
            &mut heap_with_price,
            compute_price_data(5),
            vec![],
        );
        signer
            .validate_manual_message_mutation(&heap, &heap_with_price)
            .unwrap();
        if let VersionedMessage::V0(message) = &mut heap_with_price.message {
            message.instructions[1].data[1] ^= 1;
        }
        assert!(signer
            .validate_manual_message_mutation(&heap, &heap_with_price)
            .is_err());
    }

    #[test]
    fn test_fordefi_native_manual_rejects_invalid_fee_mutations() {
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let base = create_test_transaction(&pubkey);
        let signer = create_native_manual_test_signer("https://example.com", pubkey);

        let mut original_price = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut original_price,
            compute_price_data(5),
            vec![],
        );
        signer
            .validate_manual_message_mutation(&original_price, &original_price)
            .unwrap();
        let mut changed_price = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut changed_price,
            compute_price_data(6),
            vec![],
        );
        assert!(signer
            .validate_manual_message_mutation(&original_price, &changed_price)
            .is_err());

        let mut malformed = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut malformed,
            vec![SET_COMPUTE_UNIT_LIMIT, 1],
            vec![],
        );
        let mut duplicate = base.clone();
        prepend_manual_compute_budget_instruction(&mut duplicate, compute_price_data(1), vec![]);
        prepend_manual_compute_budget_instruction(&mut duplicate, compute_price_data(2), vec![]);
        let mut account_bearing = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut account_bearing,
            compute_price_data(1),
            vec![0],
        );
        let mut out_of_range = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut out_of_range,
            compute_limit_data(MAX_COMPUTE_UNIT_LIMIT + 1),
            vec![],
        );
        let mut unknown = base.clone();
        prepend_manual_compute_budget_instruction(&mut unknown, vec![9], vec![]);
        for invalid in [malformed, duplicate, account_bearing, out_of_range, unknown] {
            assert!(signer
                .validate_manual_message_mutation(&base, &invalid)
                .is_err());
        }
    }

    #[test]
    fn test_fordefi_native_manual_enforces_custom_fee_constraints() {
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let base = create_test_v0_transaction(&pubkey);
        let mut returned = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut returned,
            compute_limit_data(200_000),
            vec![],
        );
        prepend_manual_compute_budget_instruction(&mut returned, compute_price_data(10), vec![]);

        let mut exact = create_native_manual_test_signer("https://example.com", pubkey);
        exact.fee = Some(FordefiSolanaFee::Custom {
            unit_price: Some("10".to_string()),
            priority_fee: Some("2".to_string()),
        });
        exact
            .validate_manual_message_mutation(&base, &returned)
            .unwrap();
        assert!(exact
            .validate_manual_message_mutation(&base, &base)
            .is_err());

        let mut capped = create_native_manual_test_signer("https://example.com", pubkey);
        capped.fee = Some(FordefiSolanaFee::Custom {
            unit_price: None,
            priority_fee: Some("1".to_string()),
        });
        assert!(capped
            .validate_manual_message_mutation(&base, &returned)
            .is_err());

        let mut original_price = base.clone();
        prepend_manual_compute_budget_instruction(
            &mut original_price,
            compute_price_data(10),
            vec![],
        );
        let mut conflicting = create_native_manual_test_signer("https://example.com", pubkey);
        conflicting.fee = Some(FordefiSolanaFee::Custom {
            unit_price: Some("11".to_string()),
            priority_fee: None,
        });
        assert!(conflicting
            .validate_manual_message_mutation(&original_price, &original_price)
            .is_err());
    }

    #[test]
    fn test_fordefi_native_manual_restricts_durable_nonce_lifetime() {
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer("https://example.com", pubkey);
        let mut nonce = create_test_transaction(&pubkey);
        if let VersionedMessage::Legacy(message) = &mut nonce.message {
            message.instructions[0].data = vec![4, 0, 0, 0];
        }
        assert!(nonce.uses_durable_nonce());
        let mut changed = nonce.clone();
        changed.message.set_recent_blockhash(Hash::new_unique());
        assert!(signer
            .validate_manual_message_mutation(&nonce, &changed)
            .is_err());
    }

    #[cfg(feature = "sdk-v4")]
    #[test]
    fn test_fordefi_native_manual_restricts_v1_inline_config() {
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer("https://example.com", pubkey);
        let original = create_test_v1_transaction(&pubkey);
        let mut blockhash_changed = original.clone();
        blockhash_changed
            .message
            .set_recent_blockhash(Hash::new_unique());
        signer
            .validate_manual_message_mutation(&original, &blockhash_changed)
            .unwrap();

        let mut config_changed = blockhash_changed;
        if let VersionedMessage::V1(message) = &mut config_changed.message {
            message.config.priority_fee = Some(99);
        }
        assert!(signer
            .validate_manual_message_mutation(&original, &config_changed)
            .is_err());
    }

    #[cfg(feature = "sdk-v4")]
    #[tokio::test]
    async fn test_fordefi_native_manual_replaces_v1_transaction() {
        let keypair = create_test_keypair();
        let transaction = create_test_v1_transaction(&keypair_pubkey(&keypair));
        assert_native_manual_round_trip(transaction, &keypair, "signed").await;
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_returns_partial_multisigner_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let cosigner = keypair_pubkey(&create_test_keypair());
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);

        let mut transaction = create_test_transaction(&pubkey);
        add_required_signer(&mut transaction, cosigner);
        transaction.signatures = vec![Signature::default(); 2];

        let mut returned_tx = transaction.clone();
        returned_tx.message.set_recent_blockhash(Hash::new_unique());
        let (wire_bytes, expected_signature) = signed_wire_transaction(&mut returned_tx, &keypair);
        mount_native_manual_result(
            &mock_server,
            "manual-multisigner",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        let result = signer.sign_transaction(&mut transaction).await.unwrap();
        assert!(matches!(result, SignTransactionResult::Partial(_)));
        let (serialized_transaction, signature) = result.into_signed_transaction();
        assert_eq!(signature, expected_signature);
        assert!(!serialized_transaction.is_empty());
        assert_eq!(transaction.signatures[0], expected_signature);
        assert_eq!(transaction.signatures[1], Signature::default());
        assert_eq!(
            transaction.message.serialize(),
            returned_tx.message.serialize()
        );
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_forwards_fee_configuration() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let mut signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        signer.fee = Some(FordefiSolanaFee::Custom {
            unit_price: None,
            priority_fee: Some("1000".to_string()),
        });

        let mut transaction = create_test_transaction(&pubkey);
        let mut returned_tx = transaction.clone();
        returned_tx.message.set_recent_blockhash(Hash::new_unique());
        let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "details": {
                    "push_mode": "manual",
                    "fee": { "type": "custom", "priority_fee": "1000" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "manual-fee"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/manual-fee"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "signed",
                "raw_transaction": STANDARD.encode(wire_bytes)
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        signer.sign_transaction(&mut transaction).await.unwrap();
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_presigned_input_before_submit() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        transaction.signatures[0] = keypair.sign_message(&transaction.message.serialize());

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_non_vault_fee_payer_before_submit() {
        let mock_server = MockServer::start().await;
        let vault_keypair = create_test_keypair();
        let signer =
            create_native_manual_test_signer(&mock_server.uri(), keypair_pubkey(&vault_keypair));
        let mut transaction = create_test_transaction(&keypair_pubkey(&create_test_keypair()));

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_missing_raw_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        let original_message = transaction.message.serialize();
        mount_native_manual_result(&mock_server, "manual-no-raw", "signed", None).await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
        assert_eq!(transaction.message.serialize(), original_message);
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_malformed_raw_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        mount_native_manual_result(
            &mock_server,
            "manual-malformed",
            "signed",
            Some(STANDARD.encode([1u8, 2, 3])),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SerializationError(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_oversized_raw_transaction() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        mount_native_manual_result(
            &mock_server,
            "manual-oversized",
            "signed",
            Some(STANDARD.encode(vec![0u8; SOLANA_PACKET_DATA_SIZE + 1])),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_missing_vault_signature() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        let returned_tx = transaction.clone();
        let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
        mount_native_manual_result(
            &mock_server,
            "manual-no-signature",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_invalid_vault_signature() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        let mut returned_tx = transaction.clone();
        returned_tx.signatures[0] = Signature::from([0xabu8; 64]);
        let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
        mount_native_manual_result(
            &mock_server,
            "manual-invalid-signature",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_changed_signer_set() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        let mut returned_tx = transaction.clone();
        add_required_signer(&mut returned_tx, keypair_pubkey(&create_test_keypair()));
        returned_tx.signatures = vec![Signature::default(); 2];
        let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);
        mount_native_manual_result(
            &mock_server,
            "manual-changed-signers",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_changed_instruction_content() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        let mut returned_tx = transaction.clone();
        match &mut returned_tx.message {
            VersionedMessage::Legacy(message) => message.instructions[0].data[0] ^= 0x01,
            _ => panic!("expected legacy test transaction"),
        }
        let (wire_bytes, _) = signed_wire_transaction(&mut returned_tx, &keypair);
        mount_native_manual_result(
            &mock_server,
            "manual-changed-content",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_rejects_populated_downstream_signature() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let cosigner_keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        add_required_signer(&mut transaction, keypair_pubkey(&cosigner_keypair));
        transaction.signatures = vec![Signature::default(); 2];

        let mut returned_tx = transaction.clone();
        let returned_message = returned_tx.message.serialize();
        returned_tx.signatures = vec![
            keypair.sign_message(&returned_message),
            cosigner_keypair.sign_message(&returned_message),
        ];
        let wire_bytes = serialize_wire_transaction(&returned_tx).unwrap();
        mount_native_manual_result(
            &mock_server,
            "manual-downstream-signature",
            "signed",
            Some(STANDARD.encode(wire_bytes)),
        )
        .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_failure_state_is_not_broadcast_unconfirmed() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);
        mount_native_manual_result(&mock_server, "manual-failed", "error_signing", None).await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::SigningFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_poll_timeout_is_not_broadcast_unconfirmed() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "manual-pending"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/transactions/manual-pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "pending_signature"
            })))
            .expect(3)
            .mount(&mock_server)
            .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
    }

    #[tokio::test]
    async fn test_fordefi_native_manual_submit_error_is_not_broadcast_unconfirmed() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_manual_test_signer(&mock_server.uri(), pubkey);
        let mut transaction = create_test_transaction(&pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(502))
            .expect(1)
            .mount(&mock_server)
            .await;

        assert!(matches!(
            signer.sign_transaction(&mut transaction).await.unwrap_err(),
            SignerError::RemoteApiError(_)
        ));
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
                assert_eq!(provider_tx_id.as_deref(), Some("native-tx-no-raw"));
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_native_submit_server_error_is_unconfirmed_without_a_transaction_id() {
        let mock_server = MockServer::start().await;
        let pubkey = keypair_pubkey(&create_test_keypair());
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        match signer.sign_transaction(&mut tx).await.unwrap_err() {
            SignerError::BroadcastUnconfirmed {
                provider_tx_id,
                provider_status,
                ..
            } => {
                assert_eq!(provider_tx_id, None);
                assert_eq!(provider_status, Some(502));
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_native_submit_accepted_without_an_id_is_unconfirmed() {
        let mock_server = MockServer::start().await;
        let pubkey = keypair_pubkey(&create_test_keypair());
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "pending" })),
            )
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        match signer.sign_transaction(&mut tx).await.unwrap_err() {
            SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
                assert_eq!(provider_tx_id, None);
            }
            other => panic!("Expected BroadcastUnconfirmed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_native_submit_rejected_by_fordefi_stays_a_plain_failure() {
        let mock_server = MockServer::start().await;
        let pubkey = keypair_pubkey(&create_test_keypair());
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        match signer.sign_transaction(&mut tx).await.unwrap_err() {
            SignerError::RemoteApiError(_) => {}
            other => panic!("Expected RemoteApiError, got: {other:?}"),
        }
    }

    /// Black-box mode only signs, so a failed submit has no on-chain outcome to be unconfirmed about.
    #[tokio::test]
    async fn test_black_box_submit_server_error_is_not_reported_as_unconfirmed() {
        let mock_server = MockServer::start().await;
        let pubkey = keypair_pubkey(&create_test_keypair());
        let signer = create_test_signer(&mock_server.uri(), pubkey);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&mock_server)
            .await;

        let mut tx = create_test_transaction(&pubkey);
        match signer.sign_transaction(&mut tx).await.unwrap_err() {
            SignerError::RemoteApiError(_) => {}
            other => panic!("Expected RemoteApiError, got: {other:?}"),
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
                ..
            } => {
                assert_eq!(provider_tx_id.as_deref(), Some("native-tx-fail"));
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
                ..
            } => {
                assert_eq!(provider_tx_id.as_deref(), Some("native-tx-pending"));
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
                assert_eq!(provider_tx_id.as_deref(), Some("native-tx-malformed"));
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
