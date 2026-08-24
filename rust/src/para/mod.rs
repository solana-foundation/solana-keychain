//! Para API signer integration

mod types;

use crate::remote_util::parse_json_response;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{signature_from_hex, verify_or_reject};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::TransactionUtil;
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use std::str::FromStr;
use types::{SignRawRequest, SignRawResponse, WalletResponse};

const DEFAULT_BASE_URL: &str = "https://api.getpara.com";
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const AVAILABILITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Para-based signer using Para's wallet API
#[derive(Clone)]
pub struct ParaSigner {
    api_key: String,
    wallet_id: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Pubkey,
}

/// Configuration for creating a ParaSigner.
#[derive(Clone)]
pub struct ParaSignerConfig {
    pub api_key: String,
    pub wallet_id: String,
    pub api_base_url: Option<String>,
}

impl std::fmt::Debug for ParaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParaSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl ParaSigner {
    /// Create a new ParaSigner
    ///
    /// Validates that `api_key` starts with `sk_` and `wallet_id` is a valid UUID.
    /// Call `init()` after construction to fetch the public key from Para's API.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Para API secret key (must start with `sk_`)
    /// * `wallet_id` - Para wallet UUID
    /// * `api_base_url` - Optional custom API base URL (defaults to "https://api.getpara.com")
    pub fn new(
        api_key: String,
        wallet_id: String,
        api_base_url: Option<String>,
    ) -> Result<Self, SignerError> {
        Self::from_config(ParaSignerConfig {
            api_key,
            wallet_id,
            api_base_url,
        })
    }

    /// Create a new ParaSigner from a configuration object.
    pub fn from_config(config: ParaSignerConfig) -> Result<Self, SignerError> {
        if config.api_key.is_empty() || config.wallet_id.is_empty() {
            return Err(SignerError::ConfigError(
                "apiKey and walletId must not be empty".to_string(),
            ));
        }

        if !config.api_key.starts_with("sk_") {
            return Err(SignerError::ConfigError(
                "apiKey must be a Para secret key (starts with sk_)".to_string(),
            ));
        }

        if !Self::is_valid_uuid(&config.wallet_id) {
            return Err(SignerError::ConfigError(
                "walletId must be a valid UUID".to_string(),
            ));
        }

        if let Some(ref url) = config.api_base_url {
            if !url.starts_with("https://") {
                return Err(SignerError::ConfigError(
                    "apiBaseUrl must use HTTPS".to_string(),
                ));
            }
        }

        let client = HttpClientConfig {
            request_timeout: Some(CLIENT_TIMEOUT),
            connect_timeout: None,
        }
        .build_client()?;

        Ok(Self {
            api_key: config.api_key,
            wallet_id: config.wallet_id,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
                .trim_end_matches('/')
                .to_string(),
            client,
            public_key: Pubkey::default(),
        })
    }

    /// Initialize the signer by fetching the wallet and extracting the public key
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let wallet = self.fetch_wallet().await?;

        if !wallet.wallet_type.eq_ignore_ascii_case("SOLANA") {
            return Err(SignerError::ConfigError(format!(
                "Expected SOLANA wallet, got: {}",
                wallet.wallet_type
            )));
        }

        if !wallet.status.eq_ignore_ascii_case("ACTIVE")
            && !wallet.status.eq_ignore_ascii_case("READY")
        {
            log::warn!(
                "Para wallet status is '{}' — signing may fail",
                wallet.status
            );
        }

        let address = wallet.address.ok_or_else(|| {
            SignerError::ConfigError(
                "Wallet does not have an address (may still be creating)".to_string(),
            )
        })?;

        self.public_key = Pubkey::from_str(&address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid Solana public key from Para API".to_string())
        })?;

        Ok(())
    }

    /// Fetch wallet info from Para API
    async fn fetch_wallet(&self) -> Result<WalletResponse, SignerError> {
        let url = format!("{}/v1/wallets/{}", self.api_base_url, self.wallet_id);

        let response = self
            .client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        parse_json_response(response, "Para API fetch_wallet").await
    }

    /// Sign raw bytes using Para API (hex-encoded)
    async fn sign_bytes(&self, data: &[u8]) -> Result<Signature, SignerError> {
        if self.public_key == Pubkey::default() {
            return Err(SignerError::ConfigError(
                "Signer not initialized. Call init() first.".to_string(),
            ));
        }

        let url = format!(
            "{}/v1/wallets/{}/sign-raw",
            self.api_base_url, self.wallet_id
        );

        let request = SignRawRequest {
            data: hex::encode(data),
            encoding: "hex",
        };

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await?;

        let sign_response: SignRawResponse =
            parse_json_response(response, "Para API sign_bytes").await?;

        let hex_sig = sign_response.signature.ok_or_else(|| {
            SignerError::SigningFailed("Missing signature in response".to_string())
        })?;

        let sig = signature_from_hex(&hex_sig)?;
        verify_or_reject(&sig, &self.public_key, data)?;

        Ok(sig)
    }

    /// Check wallet availability with a timeout
    async fn check_availability(&self) -> bool {
        let result = tokio::time::timeout(AVAILABILITY_TIMEOUT, self.fetch_wallet()).await;

        match result {
            Ok(Ok(wallet)) => {
                wallet.wallet_type.eq_ignore_ascii_case("SOLANA")
                    && (wallet.status.eq_ignore_ascii_case("ACTIVE")
                        || wallet.status.eq_ignore_ascii_case("READY"))
            }
            _ => false,
        }
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message.serialize()).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.pubkey(), signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }

    /// Validate UUID format (matches TS UUID_REGEX)
    fn is_valid_uuid(s: &str) -> bool {
        if s.len() != 36 {
            return false;
        }
        let bytes = s.as_bytes();
        // UUID format: 8-4-4-4-12 hex chars with dashes at positions 8, 13, 18, 23
        bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-'
            && s.replace('-', "").bytes().all(|b| b.is_ascii_hexdigit())
    }
}

#[async_trait::async_trait]
impl SolanaSigner for ParaSigner {
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

    /// Check if the signer is available. Makes a network call to the Para API
    /// with a 5-second timeout. Callers should cache the result if frequent checks are needed.
    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[cfg(test)]
mod tests;
