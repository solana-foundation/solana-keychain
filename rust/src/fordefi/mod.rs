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
use crate::remote_util::{extract_api_error, parse_json_response, poll_until, PollOutcome};
use crate::sdk_adapter::{
    CompiledInstruction, MessageHeader, Pubkey, Signature, VersionedMessage, VersionedTransaction,
    COMPUTE_BUDGET_PROGRAM_ID,
};
use crate::signature_util::signature_from_base64;
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
/// Default ceiling, in lamports, on a priority fee Fordefi introduces itself
/// during native manual signing, so a compromised or malfunctioning response
/// cannot drain the fee payer. Override via
/// [`FordefiSignerConfig::max_priority_fee_lamports`].
pub const DEFAULT_MAX_PRIORITY_FEE_LAMPORTS: u64 = 100_000_000;

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

/// Rounds up, and charges an absent limit at the runtime maximum.
fn effective_manual_priority_fee_lamports(fee: ManualFeeInstructions) -> u128 {
    let price = fee.price.unwrap_or(0) as u128;
    let limit = fee.limit.unwrap_or(MAX_COMPUTE_UNIT_LIMIT) as u128;
    (price * limit).saturating_add(MICRO_LAMPORTS_PER_LAMPORT - 1) / MICRO_LAMPORTS_PER_LAMPORT
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
    /// Who broadcasts a native Solana transaction. `None` is equivalent to
    /// [`FordefiPushMode::Auto`]; [`FordefiPushMode::Manual`] requires `chain`.
    pub push_mode: Option<FordefiPushMode>,
    /// Ceiling, in lamports, on a priority fee Fordefi introduces itself during
    /// native manual signing. `None` applies
    /// [`DEFAULT_MAX_PRIORITY_FEE_LAMPORTS`], unless `fee` sets a custom
    /// `priority_fee`, which governs instead. Never applies to a compute-unit
    /// price the caller set, since those messages are compared byte-for-byte.
    pub max_priority_fee_lamports: Option<u64>,
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
    /// `None` when the caller did not state a ceiling.
    max_priority_fee_lamports: Option<u64>,
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
    ///
    /// Set `config.push_mode` to [`FordefiPushMode::Manual`] for native signing
    /// without broadcasting; it requires `config.chain`.
    pub async fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let signer = Self::build(config)?;
        signer.verify_vault_address_with_timeout().await?;
        Ok(signer)
    }

    /// Shared construction: validate config, resolve the request-signing
    /// mechanism, and assemble the signer.
    fn build(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let push_mode = config.push_mode.unwrap_or(FordefiPushMode::Auto);
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
            max_priority_fee_lamports: config.max_priority_fee_lamports,
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

        // Only now that every check has passed.
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
        // No caller price, so any price here is Fordefi's own.
        self.validate_manual_fee_ceiling(returned_fee)?;
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
        if let (Some(configured), Some(_)) = (priority_fee, returned_fee.price) {
            let maximum = configured.parse::<u128>().map_err(|_| {
                SignerError::SigningFailed("Configured custom priority_fee is invalid".to_string())
            })?;
            if effective_manual_priority_fee_lamports(returned_fee) > maximum {
                return Err(SignerError::SigningFailed(
                    "Fordefi returned a priority fee above the configured custom priority_fee"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// `None` when a custom `priority_fee` already bounds the total.
    fn manual_priority_fee_ceiling(&self) -> Option<u128> {
        if let Some(configured) = self.max_priority_fee_lamports {
            return Some(configured as u128);
        }
        if let Some(FordefiSolanaFee::Custom {
            priority_fee: Some(_),
            ..
        }) = &self.fee
        {
            return None;
        }
        Some(DEFAULT_MAX_PRIORITY_FEE_LAMPORTS as u128)
    }

    /// Enforces [`DEFAULT_MAX_PRIORITY_FEE_LAMPORTS`] or the configured override.
    fn validate_manual_fee_ceiling(
        &self,
        returned_fee: ManualFeeInstructions,
    ) -> Result<(), SignerError> {
        if returned_fee.price.is_none() {
            return Ok(());
        }
        let Some(ceiling) = self.manual_priority_fee_ceiling() else {
            return Ok(());
        };
        if effective_manual_priority_fee_lamports(returned_fee) > ceiling {
            return Err(SignerError::SigningFailed(
                "Fordefi returned a priority fee above the configured maximum; raise \
                 max_priority_fee_lamports to allow it"
                    .to_string(),
            ));
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

        parse_json_response(response, "Fordefi API fetch_vault").await
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
mod tests;
