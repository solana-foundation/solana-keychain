//! CDP (Coinbase Developer Platform) signer integration

mod jwt;
mod types;

use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::{
    deserialize_wire_transaction, serialize_wire_transaction, TransactionUtil,
};
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::str::FromStr;

use self::jwt::{create_auth_jwt, create_wallet_jwt};
use self::types::{SignMessageResponse, SignTransactionResponse};
use crate::wallet_jwt::extract_host;

use crate::remote_util::parse_json_response;
use crate::signature_util::{signature_from_base58, verify_or_reject};

const CDP_API_HOST: &str = "api.cdp.coinbase.com";
const CDP_BASE_PATH: &str = "/platform/v2/solana/accounts";

// ─── CdpSigner ────────────────────────────────────────────────────────────────

/// CDP (Coinbase Developer Platform) Solana signer.
///
/// Signs Solana transactions and messages using CDP's managed key infrastructure
/// via the CDP REST API. The account address must be provided at construction time.
///
/// # Authentication
///
/// CDP uses two JWTs per signing request:
/// - `Authorization: Bearer <jwt>` — main API auth (Ed25519 or ES256)
/// - `X-Wallet-Auth: <jwt>` — wallet auth for write endpoints (ES256)
///
/// # Example
///
/// ```rust,no_run
/// use solana_keychain::{CdpSigner, SolanaSigner};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let signer = CdpSigner::new(
///         std::env::var("CDP_API_KEY_ID")?,
///         std::env::var("CDP_API_KEY_SECRET")?,
///         std::env::var("CDP_WALLET_SECRET")?,
///         std::env::var("CDP_SOLANA_ADDRESS")?,
///     )?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct CdpSigner {
    api_key_id: String,
    api_key_secret: String,
    wallet_secret: String,
    public_key: Pubkey,
    api_base_url: String,
    api_host: String,
    client: reqwest::Client,
}

/// Configuration for creating a CdpSigner.
#[derive(Clone)]
pub struct CdpSignerConfig {
    pub api_key_id: String,
    pub api_key_secret: String,
    pub wallet_secret: String,
    pub address: String,
    pub api_base_url: Option<String>,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for CdpSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdpSigner")
            .field("public_key", &self.public_key)
            .field("api_base_url", &self.api_base_url)
            .finish_non_exhaustive()
    }
}

impl CdpSigner {
    /// Create a new CdpSigner.
    ///
    /// # Arguments
    ///
    /// * `api_key_id` - CDP API key name / ID
    /// * `api_key_secret` - CDP API private key (base64 Ed25519)
    /// * `wallet_secret` - CDP wallet secret (base64 PKCS#8 DER for ES256)
    /// * `address` - Solana account address managed by CDP (base58 pubkey)
    pub fn new(
        api_key_id: String,
        api_key_secret: String,
        wallet_secret: String,
        address: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(CdpSignerConfig {
            api_key_id,
            api_key_secret,
            wallet_secret,
            address,
            api_base_url: None,
            http_client_config: None,
        })
    }

    /// Create a new CdpSigner from a configuration object.
    pub fn from_config(config: CdpSignerConfig) -> Result<Self, SignerError> {
        if config.api_key_id.is_empty() {
            return Err(SignerError::ConfigError(
                "api_key_id must not be empty".to_string(),
            ));
        }
        if config.api_key_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "api_key_secret must not be empty".to_string(),
            ));
        }
        if config.wallet_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "wallet_secret must not be empty".to_string(),
            ));
        }
        if config.address.is_empty() {
            return Err(SignerError::ConfigError(
                "address must not be empty".to_string(),
            ));
        }

        let public_key = Pubkey::from_str(&config.address).map_err(|_| {
            SignerError::InvalidPublicKey(format!("Invalid Solana address: {}", config.address))
        })?;

        let base_url = config
            .api_base_url
            .unwrap_or_else(|| format!("https://{CDP_API_HOST}"));
        let api_host = extract_host(&base_url, "CDP")?;
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config.build_client()?;

        Ok(Self {
            api_key_id: config.api_key_id,
            api_key_secret: config.api_key_secret,
            wallet_secret: config.wallet_secret,
            public_key,
            api_base_url: base_url,
            api_host,
            client,
        })
    }

    /// Build authenticated request headers for a given method and path.
    fn build_auth_headers(
        &self,
        method: &str,
        path: &str,
        request_body: Option<&Value>,
    ) -> Result<reqwest::header::HeaderMap, SignerError> {
        let auth_token = create_auth_jwt(
            &self.api_key_id,
            &self.api_key_secret,
            &self.api_host,
            method,
            path,
        )?;
        let wallet_token = create_wallet_jwt(
            &self.wallet_secret,
            &self.api_host,
            method,
            path,
            request_body,
        )?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {auth_token}")
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid auth token".to_string()))?,
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            reqwest::header::HeaderName::from_static("x-wallet-auth"),
            wallet_token
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid wallet token".to_string()))?,
        );

        Ok(headers)
    }

    /// Build auth headers for GET requests (no wallet auth needed).
    fn build_get_headers(&self, path: &str) -> Result<reqwest::header::HeaderMap, SignerError> {
        let auth_token = create_auth_jwt(
            &self.api_key_id,
            &self.api_key_secret,
            &self.api_host,
            "GET",
            path,
        )?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {auth_token}")
                .parse()
                .map_err(|_| SignerError::SigningFailed("Invalid auth token".to_string()))?,
        );

        Ok(headers)
    }

    /// Sign a Solana transaction via the CDP API.
    async fn call_sign_transaction(
        &self,
        base64_tx: &str,
    ) -> Result<SignTransactionResponse, SignerError> {
        let path = format!("{}/{}/sign/transaction", CDP_BASE_PATH, self.public_key);
        let url = format!("{}{}", self.api_base_url, path);

        let body = serde_json::json!({ "transaction": base64_tx });
        let headers = self.build_auth_headers("POST", &path, Some(&body))?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("CDP HTTP request failed: {e}")))?;

        parse_json_response(response, "CDP sign_transaction").await
    }

    /// Sign a message via the CDP API.
    async fn call_sign_message(&self, message: &str) -> Result<SignMessageResponse, SignerError> {
        let path = format!("{}/{}/sign/message", CDP_BASE_PATH, self.public_key);
        let url = format!("{}{}", self.api_base_url, path);

        let body = serde_json::json!({ "message": message });
        let headers = self.build_auth_headers("POST", &path, Some(&body))?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("CDP HTTP request failed: {e}")))?;

        parse_json_response(response, "CDP sign_message").await
    }

    /// Sign message bytes using the CDP API.
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // CDP signMessage API takes a UTF-8 string
        let message_str = std::str::from_utf8(message).map_err(|_e| {
            SignerError::SerializationError(
                "CDP signMessage requires UTF-8; non-UTF-8 bytes are not supported".to_string(),
            )
        })?;
        let response = self.call_sign_message(message_str).await?;

        // CDP returns a base58-encoded signature
        let sig = signature_from_base58(&response.signature)?;
        verify_or_reject(&sig, &self.public_key, message)?;

        Ok(sig)
    }

    /// Sign and serialize a Solana transaction via CDP.
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let message_data = transaction.message.serialize();
        let signer_position =
            TransactionUtil::get_signing_keypair_position(transaction, &self.public_key)?;

        // Serialize the full transaction to bytes (Solana wire format)
        let serialized = serialize_wire_transaction(transaction)?;
        let base64_tx = STANDARD.encode(&serialized);

        let response = self.call_sign_transaction(&base64_tx).await?;

        // Decode and deserialize the returned signed transaction
        let signed_bytes = STANDARD
            .decode(&response.signed_transaction)
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to decode base64 signed transaction: {_e}");
                SignerError::SerializationError(
                    "Failed to decode base64 signed transaction from CDP".to_string(),
                )
            })?;

        let signed_tx: VersionedTransaction =
            deserialize_wire_transaction(&signed_bytes).map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to deserialize signed transaction: {_e}");
                SignerError::SerializationError(
                    "Failed to deserialize signed transaction from CDP".to_string(),
                )
            })?;

        // Extract only our signature from the response and apply it to the original transaction.
        let signature = *signed_tx.signatures.get(signer_position).ok_or_else(|| {
            SignerError::SigningFailed(
                "Signature not found at expected position in CDP response".to_string(),
            )
        })?;

        verify_or_reject(&signature, &self.public_key, &message_data)?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Check if CDP API is reachable by fetching the account info.
    async fn check_availability(&self) -> bool {
        let path = format!("{}/{}", CDP_BASE_PATH, self.public_key);

        let headers = match self.build_get_headers(&path) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let url = format!("{}{}", self.api_base_url, path);
        match self.client.get(&url).headers(headers).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

// ─── SolanaSigner Implementation ─────────────────────────────────────────────

#[async_trait::async_trait]
impl SolanaSigner for CdpSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
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
        self.sign_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
