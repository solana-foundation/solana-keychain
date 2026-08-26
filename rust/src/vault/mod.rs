//! HashiCorp Vault signer integration

/// Re-export of the [`reqwest`] crate used internally by this module,
/// so callers of [`VaultSigner::with_client_builder`] can construct a
/// `ClientBuilder` at exactly the version this crate links against —
/// avoiding the version-mismatch footgun of depending on `reqwest`
/// directly in their own `Cargo.toml`.
pub use reqwest;

use crate::remote_util::parse_json_response;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{signature_from_base64, verify_or_reject};
use crate::traits::{SignTransactionResult, SignedTransaction};
use crate::{
    error::SignerError, http_client_config::HttpClientConfig, traits::SolanaSigner,
    transaction_util::TransactionUtil,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

/// Vault-based signer using HashiCorp Vault transit engine
#[derive(Clone)]
pub struct VaultSigner {
    client: Arc<Client>,
    api_base_url: String,
    token: String,
    key_name: String,
    public_key: Pubkey,
}

/// Configuration for creating a VaultSigner.
#[derive(Clone)]
pub struct VaultSignerConfig {
    pub api_base_url: String,
    pub token: String,
    pub key_name: String,
    pub public_key: String,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for VaultSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl VaultSigner {
    fn strip_vault_signature_prefix(signature: &str) -> &str {
        let Some(rest) = signature.strip_prefix("vault:v") else {
            return signature;
        };

        let Some((version, encoded_signature)) = rest.split_once(':') else {
            return signature;
        };

        if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()) {
            return signature;
        }

        encoded_signature
    }

    /// Creates a new Vault signer
    ///
    /// # Arguments
    ///
    /// * `api_base_url` - Vault server address (e.g., "https://vault.example.com")
    /// * `token` - Vault authentication token
    /// * `key_name` - Vault key name in transit engine
    /// * `public_key` - Base58-encoded public key
    pub fn new(
        api_base_url: String,
        token: String,
        key_name: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(VaultSignerConfig {
            api_base_url,
            token,
            key_name,
            public_key,
            http_client_config: None,
        })
    }

    /// Creates a new Vault signer from a configuration object.
    pub fn from_config(config: VaultSignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();

        Self::with_client_builder(
            http_client_config.client_builder(),
            config.api_base_url,
            config.token,
            config.key_name,
            config.public_key,
        )
    }

    /// Creates a Vault signer from a caller-configured [`reqwest::ClientBuilder`].
    ///
    /// Use this when you need control over TLS configuration, proxies,
    /// timeouts, or other client-level settings that `HttpClientConfig`
    /// does not expose — for example, trusting a self-signed CA via
    /// `Client::builder().add_root_certificate(..)` when talking to a
    /// development Vault instance.
    ///
    /// The builder is finished with this crate's no-redirect policy (a
    /// builder rather than a built `Client` so the policy cannot be
    /// bypassed): requests carry `X-Vault-Token`, and a redirect-following
    /// client would replay it to the redirect target. `https_only` is
    /// deliberately not forced — Vault is routinely reached over plain-HTTP
    /// loopback (e.g. `vault server -dev`), so transport security stays the
    /// caller's choice.
    ///
    /// To avoid pulling `reqwest` into your own dependency tree at a
    /// version that may diverge from `solana-keychain`'s, prefer
    /// constructing the builder via the re-exported
    /// [`solana_keychain::vault::reqwest`] module.
    ///
    /// # Arguments
    ///
    /// * `client_builder` - A caller-configured reqwest `ClientBuilder`.
    /// * `api_base_url` - Vault server address (e.g., "https://vault.example.com")
    /// * `token` - Vault authentication token
    /// * `key_name` - Vault key name in transit engine
    /// * `public_key` - Base58-encoded public key
    pub fn with_client_builder(
        client_builder: reqwest::ClientBuilder,
        api_base_url: String,
        token: String,
        key_name: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let client = client_builder
            .redirect(crate::http_client_config::no_redirect_policy())
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        let public_key = std::str::FromStr::from_str(&public_key)
            .map_err(|_| SignerError::InvalidPublicKey("Invalid public key".to_string()))?;

        Ok(Self {
            client: Arc::new(client),
            api_base_url,
            token,
            key_name,
            public_key,
        })
    }

    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        let url = format!("{}/v1/transit/sign/{}", self.api_base_url, self.key_name);

        let payload = json!({
            "input": STANDARD.encode(serialized)
        });

        let response = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SignerError::RemoteApiError(format!("Failed to send request to Vault: {e}"))
            })?;

        let result: serde_json::Value = parse_json_response(response, "Vault API").await?;

        let signature_b64 = result["data"]["signature"].as_str().ok_or_else(|| {
            SignerError::RemoteApiError("No signature in Vault response".to_string())
        })?;

        // Remove a versioned Vault transit prefix (e.g., "vault:v1:", "vault:v2:", ...).
        let signature_b64 = Self::strip_vault_signature_prefix(signature_b64);

        let sig = signature_from_base64(signature_b64)?;
        verify_or_reject(&sig, &self.public_key, serialized)?;

        Ok(sig)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message.serialize()).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.public_key, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for VaultSigner {
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
        // Check if we can read and validate key metadata as a health check.
        let url = format!("{}/v1/transit/keys/{}", self.api_base_url, self.key_name);

        let response = match self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => return false,
        };

        if !response.status().is_success() {
            return false;
        }

        let body = match crate::remote_util::read_body_capped(response).await {
            Ok(body) => body,
            Err(_) => return false,
        };
        let body: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(_) => return false,
        };

        let supports_signing = body["data"]["supports_signing"].as_bool() == Some(true);
        let key_type_is_ed25519 = body["data"]["type"].as_str() == Some("ed25519");

        supports_signing && key_type_is_ed25519
    }
}

#[cfg(test)]
mod tests;
