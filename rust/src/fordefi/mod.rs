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
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
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

/// Configuration for creating a FordefiSigner.
#[derive(Clone)]
pub struct FordefiSignerConfig {
    /// Fordefi API bearer token
    pub access_token: String,
    /// Fordefi vault UUID
    pub vault_id: String,
    /// PEM-encoded ECDSA P-256 private key for API request signing
    pub private_key_pem: String,
    /// Solana public key of the vault (base58)
    pub public_key: String,
    /// Optional API base URL (default: "https://api.fordefi.com")
    pub api_base_url: Option<String>,
    /// Polling interval in milliseconds (default: 2000)
    pub poll_interval_ms: Option<u64>,
    /// Max polling attempts (default: 50)
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
///   serialized transaction is **empty** — only the signature is returned. The caller's
///   `&mut Transaction` is updated to the Fordefi-signed transaction.
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
    /// The request-signing key is parsed from `config.private_key_pem` (PEM-encoded
    /// ECDSA P-256). To keep that key in a KMS/HSM instead, implement
    /// [`FordefiRequestSigner`] and use [`FordefiSigner::from_config_with_signer`].
    pub fn from_config(config: FordefiSignerConfig) -> Result<Self, SignerError> {
        let request_signer = Arc::new(PemRequestSigner::from_pem(&config.private_key_pem)?);
        Self::build(config, request_signer)
    }

    /// Create a new FordefiSigner with a custom [`FordefiRequestSigner`] for
    /// API-request signing (e.g. a KMS/HSM-backed implementation).
    ///
    /// `config.private_key_pem` is ignored on this path.
    pub fn from_config_with_signer(
        config: FordefiSignerConfig,
        request_signer: Arc<dyn FordefiRequestSigner>,
    ) -> Result<Self, SignerError> {
        Self::build(config, request_signer)
    }

    /// Shared construction: validate config and assemble the signer. Does not
    /// touch `config.private_key_pem` — request signing is provided by the
    /// injected `request_signer`.
    fn build(
        config: FordefiSignerConfig,
        request_signer: Arc<dyn FordefiRequestSigner>,
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

        if let Some(ref url) = config.api_base_url {
            if !url.starts_with("https://") {
                return Err(SignerError::ConfigError(
                    "api_base_url must use HTTPS".to_string(),
                ));
            }
        }

        if config.fee.is_some() && config.chain.is_none() {
            return Err(SignerError::ConfigError(
                "fee requires chain to be set (native Solana mode)".to_string(),
            ));
        }

        let public_key = Pubkey::from_str(&config.public_key)
            .map_err(|_| SignerError::InvalidPublicKey("Invalid Solana public key".to_string()))?;

        let http = config.http_client_config.unwrap_or_default();
        let builder = reqwest::Client::builder()
            .timeout(http.resolved_request_timeout())
            .connect_timeout(http.resolved_connect_timeout());

        #[cfg(not(test))]
        let builder = builder.https_only(true);

        let client = builder
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            access_token: config.access_token,
            vault_id: config.vault_id,
            request_signer,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            client,
            public_key,
            poll_interval_ms: config.poll_interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS),
            max_poll_attempts: config
                .max_poll_attempts
                .unwrap_or(DEFAULT_MAX_POLL_ATTEMPTS),
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
    ) -> Result<String, SignerError> {
        let path = "/api/v1/transactions";
        let body = serde_json::to_string(request)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SignerError::Other(format!("System time error: {e}")))?
            .as_millis() as u64;
        let signature = self.sign_request(path, timestamp, &body).await?;

        let url = format!("{}{}", self.api_base_url, path);
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("x-signature", &signature)
            .header("x-timestamp", timestamp.to_string())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

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

        self.submit_request(&request).await
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

        self.submit_request(&request).await
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

        self.submit_request(&request).await
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
        for _attempt in 0..self.max_poll_attempts {
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
            if _attempt + 1 < self.max_poll_attempts {
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

    /// Sign a transaction via the black box path: submit → poll → apply signature.
    async fn sign_and_serialize_black_box(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message_data();
        let tx_id = self.submit_black_box_signature(&message_data).await?;
        let signature = self.poll_for_signature(&tx_id).await?;

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
    /// replaced with the Fordefi-returned transaction.
    ///
    /// Because native mode uses `push_mode: "auto"`, Fordefi has already broadcast
    /// the transaction on-chain by the time this returns. Re-sending it would be
    /// superfluous, so the returned serialized-transaction string is intentionally
    /// empty — only the signature is returned. Callers that need the exact
    /// broadcast bytes can serialize the (now Fordefi-signed) `transaction`.
    ///
    /// Only legacy transactions are supported: a versioned (v0) transaction
    /// returned by Fordefi fails to deserialize with a [`SignerError::SerializationError`].
    async fn sign_and_serialize_native(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message_data();
        let tx_id = self.submit_solana_transaction(&message_data).await?;
        let result = self.poll_for_result(&tx_id, true).await?;

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
        let returned_tx: Transaction = bincode::deserialize(&wire_bytes).map_err(|e| {
            SignerError::SerializationError(format!(
                "Failed to deserialize Fordefi wire transaction (versioned/v0 \
                 transactions are not supported, only legacy): {e}"
            ))
        })?;

        let signature = *returned_tx.signatures.first().ok_or_else(|| {
            SignerError::SigningFailed("Fordefi wire transaction has no signatures".to_string())
        })?;

        // Verify against the *returned* message (Fordefi modifies the tx, e.g. blockhash)
        let returned_message = returned_tx.message_data();
        if !signature.verify(&self.public_key.to_bytes(), &returned_message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed against Fordefi-returned message".to_string(),
            ));
        }

        // Replace the caller's transaction with the Fordefi-signed one
        *transaction = returned_tx;

        // Native mode auto-broadcasts (push_mode: "auto"), so there is nothing for
        // the caller to send. Return an empty serialized transaction rather than
        // re-broadcastable bytes; the signature is still returned.
        Ok((String::new(), signature))
    }

    /// Sign a transaction end-to-end, dispatching to black box or native path.
    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        if self.chain.is_some() {
            self.sign_and_serialize_native(transaction).await
        } else {
            self.sign_and_serialize_black_box(transaction).await
        }
    }

    /// Check vault availability by fetching vault info.
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

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let tx_id = if self.chain.is_some() {
            self.submit_solana_message(message).await?
        } else {
            self.submit_black_box_signature(message).await?
        };
        let signature = self.poll_for_signature(&tx_id).await?;

        if !signature.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed".to_string(),
            ));
        }

        Ok(signature)
    }

    async fn is_available(&self) -> bool {
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, self.fetch_vault()).await;
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
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let secret_key: p256::SecretKey = signing_key.into();
        secret_key
            .to_sec1_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn test_request_signer() -> Arc<dyn FordefiRequestSigner> {
        Arc::new(PemRequestSigner::from_pem(&test_pem_key()).unwrap())
    }

    /// Build a black-box FordefiSigner for tests, backed by `request_signer`.
    fn create_test_signer_with(
        base_url: &str,
        pubkey: Pubkey,
        request_signer: Arc<dyn FordefiRequestSigner>,
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
            chain: None,
            fee: None,
        }
    }

    /// Helper to build a black-box FordefiSigner for tests with a mock server URL.
    fn create_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
        create_test_signer_with(base_url, pubkey, test_request_signer())
    }

    /// Helper to build a native-Solana FordefiSigner for tests.
    fn create_native_test_signer(base_url: &str, pubkey: Pubkey) -> FordefiSigner {
        FordefiSigner {
            access_token: "test-token".to_string(),
            vault_id: "test-vault-id".to_string(),
            request_signer: test_request_signer(),
            api_base_url: base_url.to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            public_key: pubkey,
            poll_interval_ms: 10,
            max_poll_attempts: 3,
            chain: Some(SolanaChainUniqueId::SolanaMainnet),
            fee: None,
        }
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
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_empty_vault_id() {
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "".to_string(),
            private_key_pem: pem,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_invalid_pem() {
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: "not-a-valid-pem".to_string(),
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPrivateKey(_)
        ));
    }

    #[test]
    fn test_fordefi_config_invalid_pubkey() {
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: "not-a-pubkey".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::InvalidPublicKey(_)
        ));
    }

    #[test]
    fn test_fordefi_config_rejects_http_url() {
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: Some("http://insecure.example.com".to_string()),
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_fee_without_chain_rejected() {
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: Some(FordefiSolanaFee::Priority {
                priority_level: FordefiPriorityLevel::High,
            }),
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }

    #[test]
    fn test_fordefi_config_with_chain_valid() {
        let pem = test_pem_key();
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: pubkey_str,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: Some(SolanaChainUniqueId::SolanaDevnet),
            fee: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_fordefi_config_valid() {
        let pem = test_pem_key();
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: pubkey_str,
            api_base_url: None,
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_ok());
        let signer = result.unwrap();
        assert_eq!(signer.api_base_url, "https://api.fordefi.com");
        assert_eq!(signer.public_key, keypair_pubkey(&keypair));
    }

    #[test]
    fn test_fordefi_config_strips_trailing_slash() {
        let pem = test_pem_key();
        let result = FordefiSigner::from_config(FordefiSignerConfig {
            access_token: "token".to_string(),
            vault_id: "vault-id".to_string(),
            private_key_pem: pem,
            public_key: "11111111111111111111111111111111".to_string(),
            api_base_url: Some("https://custom.api.com/".to_string()),
            poll_interval_ms: None,
            max_poll_attempts: None,
            http_client_config: None,
            chain: None,
            fee: None,
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().api_base_url, "https://custom.api.com");
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
        let message_data = tx.message_data();
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

    #[tokio::test]
    async fn test_fordefi_native_sign_transaction_success() {
        let mock_server = MockServer::start().await;
        let keypair = create_test_keypair();
        let pubkey = keypair_pubkey(&keypair);
        let signer = create_native_test_signer(&mock_server.uri(), pubkey);

        let tx = create_test_transaction(&pubkey);
        let message_data = tx.message_data();

        let wire_bytes = build_mock_wire_transaction(&keypair, &message_data);
        let wire_b64 = STANDARD.encode(&wire_bytes);

        Mock::given(method("POST"))
            .and(path("/api/v1/transactions"))
            .and(header("Authorization", "Bearer test-token"))
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
        let (serialized_tx, sig) = result.unwrap().into_signed_transaction();
        // Native mode auto-broadcasts, so no re-sendable wire tx is returned.
        assert!(
            serialized_tx.is_empty(),
            "native mode should return an empty serialized transaction"
        );
        assert!(sig.verify(&pubkey.to_bytes(), &message_data));
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
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
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
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
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
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignerError::SerializationError(_)
        ));
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
        let signer = create_test_signer_with(&mock_server.uri(), pubkey, Arc::new(FailingSigner));

        // Signing fails before any HTTP request is made, so no mock is needed.
        let result = signer.sign_message(b"test").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::SigningFailed(_)));
    }

    #[test]
    fn test_fordefi_from_config_with_signer_ignores_pem() {
        let keypair = create_test_keypair();
        let pubkey_str = keypair_pubkey(&keypair).to_string();

        // `private_key_pem` is intentionally invalid: it must be ignored when a
        // custom request signer is supplied.
        let result = FordefiSigner::from_config_with_signer(
            FordefiSignerConfig {
                access_token: "token".to_string(),
                vault_id: "vault-id".to_string(),
                private_key_pem: "not-a-valid-pem".to_string(),
                public_key: pubkey_str,
                api_base_url: None,
                poll_interval_ms: None,
                max_poll_attempts: None,
                http_client_config: None,
                chain: None,
                fee: None,
            },
            Arc::new(CannedSigner("x")),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fordefi_from_config_with_signer_still_validates_config() {
        // Shared validation still runs on the custom-signer path.
        let result = FordefiSigner::from_config_with_signer(
            FordefiSignerConfig {
                access_token: "".to_string(),
                vault_id: "vault-id".to_string(),
                private_key_pem: String::new(),
                public_key: "11111111111111111111111111111111".to_string(),
                api_base_url: None,
                poll_interval_ms: None,
                max_poll_attempts: None,
                http_client_config: None,
                chain: None,
                fee: None,
            },
            Arc::new(CannedSigner("x")),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::ConfigError(_)));
    }
}
