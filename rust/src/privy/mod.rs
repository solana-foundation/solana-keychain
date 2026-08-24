//! Privy API signer integration

mod authorization;
mod types;

use crate::remote_util::{extract_api_error, parse_json_response};
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{signature_from_base64, verify_or_reject};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::transaction_util::{
    deserialize_wire_transaction, serialize_wire_transaction, TransactionUtil,
};
use crate::{error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner};
use authorization::prepare_privy_authorization_headers;
pub use authorization::{
    default_privy_authorization_request_expiry_ms, format_privy_authorization_signature_payload,
    generate_privy_authorization_signatures, PrivyAuthorizationConfig, PrivyAuthorizationContext,
    PrivyAuthorizationContextProvider, PrivyAuthorizationRequestExpiry,
    PrivyAuthorizationRequestInput, PrivyAuthorizationSignFn,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::str::FromStr;
use types::{
    SignMessageParams, SignMessageRequest, SignMessageResponse, SignTransactionParams,
    SignTransactionRequest, SignTransactionResponse, WalletResponse,
};

/// Privy-based signer using Privy's wallet API
#[derive(Clone)]
pub struct PrivySigner {
    app_id: String,
    app_secret: String,
    wallet_id: String,
    api_base_url: String,
    client: reqwest::Client,
    public_key: Option<Pubkey>,
    authorization_context: Option<PrivyAuthorizationConfig>,
    authorization_request_expiry_ms: Option<u64>,
}

/// Configuration for creating a PrivySigner.
#[derive(Clone)]
pub struct PrivySignerConfig {
    pub app_id: String,
    pub app_secret: String,
    pub wallet_id: String,
    pub api_base_url: Option<String>,
    pub http_client_config: Option<HttpClientConfig>,
    pub authorization_context: Option<PrivyAuthorizationConfig>,
    pub authorization_request_expiry: PrivyAuthorizationRequestExpiry,
}

impl std::fmt::Debug for PrivySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivySigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl PrivySigner {
    /// Create a new PrivySigner
    ///
    /// # Arguments
    ///
    /// * `app_id` - Privy application ID
    /// * `app_secret` - Privy application secret
    /// * `wallet_id` - Privy wallet ID
    pub fn new(app_id: String, app_secret: String, wallet_id: String) -> Result<Self, SignerError> {
        Self::from_config(PrivySignerConfig {
            app_id,
            app_secret,
            wallet_id,
            api_base_url: None,
            http_client_config: None,
            authorization_context: None,
            authorization_request_expiry: PrivyAuthorizationRequestExpiry::Default,
        })
    }

    /// Create a new PrivySigner from a configuration object.
    pub fn from_config(config: PrivySignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config.build_client()?;

        let authorization_request_expiry_ms = match config.authorization_request_expiry {
            PrivyAuthorizationRequestExpiry::Default => {
                Some(default_privy_authorization_request_expiry_ms())
            }
            PrivyAuthorizationRequestExpiry::Milliseconds(request_expiry_ms) => {
                Some(request_expiry_ms)
            }
            PrivyAuthorizationRequestExpiry::Omit => None,
        };

        Ok(Self {
            app_id: config.app_id,
            app_secret: config.app_secret,
            wallet_id: config.wallet_id,
            api_base_url: config
                .api_base_url
                .unwrap_or_else(|| "https://api.privy.io/v1".to_string()),
            client,
            // Public key is resolved during init().
            public_key: None,
            authorization_context: config.authorization_context,
            authorization_request_expiry_ms,
        })
    }

    /// Configure Privy wallet authorization context for signing requests.
    pub fn with_authorization_context(
        mut self,
        authorization_context: impl Into<PrivyAuthorizationConfig>,
    ) -> Self {
        self.authorization_context = Some(authorization_context.into());
        self
    }

    /// Configure request-expiry window in milliseconds for authorization signatures.
    pub fn with_authorization_request_expiry_ms(mut self, request_expiry_ms: u64) -> Self {
        self.authorization_request_expiry_ms = Some(request_expiry_ms);
        self
    }

    /// Omit `privy-request-expiry` from authorization signatures and request headers.
    pub fn without_authorization_request_expiry(mut self) -> Self {
        self.authorization_request_expiry_ms = None;
        self
    }

    /// Initialize the signer by fetching the public key
    pub async fn init(&mut self) -> Result<(), SignerError> {
        let pubkey = self.fetch_public_key().await?;
        self.public_key = Some(pubkey);
        Ok(())
    }

    fn initialized_pubkey(&self) -> Result<Pubkey, SignerError> {
        self.public_key.ok_or_else(|| {
            SignerError::ConfigError(
                "PrivySigner is not initialized; call init() before signing".to_string(),
            )
        })
    }

    /// Get the Basic Auth header value
    fn get_privy_auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.app_id, self.app_secret);
        format!("Basic {}", STANDARD.encode(credentials))
    }

    /// Fetch the public key from Privy API
    async fn fetch_public_key(&self) -> Result<Pubkey, SignerError> {
        let url = format!("{}/wallets/{}", self.api_base_url, self.wallet_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", self.get_privy_auth_header())
            .header("privy-app-id", &self.app_id)
            .send()
            .await?;

        let wallet_info: WalletResponse =
            parse_json_response(response, "Privy API fetch_public_key").await?;

        // For Solana wallets, the address is the public key
        Pubkey::from_str(&wallet_info.address).map_err(|_| {
            SignerError::InvalidPublicKey("Invalid public key from Privy API".to_string())
        })
    }

    /// POST a wallet RPC request with Privy auth and authorization-signature
    /// headers, returning the response body on 2xx.
    async fn post_rpc<T: serde::Serialize>(&self, request: &T) -> Result<String, SignerError> {
        let url = format!("{}/wallets/{}/rpc", self.api_base_url, self.wallet_id);

        let authorization_headers = prepare_privy_authorization_headers(
            &self.app_id,
            self.authorization_context.as_ref(),
            "POST",
            &url,
            request,
            self.authorization_request_expiry_ms,
        )?;

        let mut request_builder = self
            .client
            .post(&url)
            .header("Authorization", self.get_privy_auth_header())
            .header("privy-app-id", &self.app_id)
            .header("Content-Type", "application/json");
        if let Some(authorization_signature) = authorization_headers.authorization_signature {
            request_builder =
                request_builder.header("privy-authorization-signature", authorization_signature);
        }
        if let Some(request_expiry) = authorization_headers.request_expiry {
            request_builder = request_builder.header("privy-request-expiry", request_expiry);
        }

        let response = request_builder.json(request).send().await?;

        if !response.status().is_success() {
            return Err(extract_api_error(response, "Privy API rpc").await);
        }

        Ok(response.text().await?)
    }

    /// Sign message bytes using Privy API
    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        let public_key = self.initialized_pubkey()?;

        let request = SignMessageRequest {
            method: "signMessage",
            chain_type: "solana",
            params: SignMessageParams {
                message: STANDARD.encode(serialized),
                encoding: "base64",
            },
        };

        let response_text = self.post_rpc(&request).await?;
        let sign_response: SignMessageResponse = serde_json::from_str(&response_text)?;

        let sig = signature_from_base64(&sign_response.data.signature)?;
        verify_or_reject(&sig, &public_key, serialized)?;

        Ok(sig)
    }

    /// Sign via Privy's `signTransaction` RPC, submitting the full wire
    /// transaction so wallet policies with transaction conditions apply.
    /// Policies must allow the `signTransaction` method.
    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let public_key = self.initialized_pubkey()?;

        let unsigned_wire = serialize_wire_transaction(transaction)?;
        let request = SignTransactionRequest {
            method: "signTransaction",
            chain_type: "solana",
            params: SignTransactionParams {
                transaction: STANDARD.encode(&unsigned_wire),
                encoding: "base64",
            },
        };

        let response_text = self.post_rpc(&request).await?;
        let sign_response: SignTransactionResponse = serde_json::from_str(&response_text)?;

        let signed_wire = STANDARD
            .decode(&sign_response.data.signed_transaction)
            .map_err(|_| {
                SignerError::SerializationError(
                    "Failed to decode signed transaction returned by Privy".to_string(),
                )
            })?;
        let returned: VersionedTransaction =
            deserialize_wire_transaction(&signed_wire).map_err(|e| {
                SignerError::SerializationError(format!(
                    "Failed to deserialize signed transaction returned by Privy: {e}"
                ))
            })?;

        let position = TransactionUtil::get_signing_keypair_position(&returned, &public_key)?;
        let signature = returned.signatures.get(position).copied().ok_or_else(|| {
            SignerError::SigningFailed(
                "Privy signature slot missing from returned transaction".to_string(),
            )
        })?;

        verify_or_reject(&signature, &public_key, &transaction.message.serialize())?;

        TransactionUtil::add_signature_to_transaction(transaction, &public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for PrivySigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key.expect("PrivySigner not initialized")
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
        // Ensure signer was initialized before attempting remote availability check.
        let Some(public_key) = self.public_key else {
            return false;
        };

        match self.fetch_public_key().await {
            Ok(pubkey) => pubkey == public_key,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests;
