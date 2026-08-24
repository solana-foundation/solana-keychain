//! HashiCorp Vault signer integration

/// Re-export of the [`reqwest`] crate used internally by this module,
/// so callers of [`VaultSigner::with_client`] can construct a `Client`
/// at exactly the version this crate links against — avoiding the
/// version-mismatch footgun of depending on `reqwest` directly in
/// their own `Cargo.toml`.
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
    vault_addr: String,
    token: String,
    key_name: String,
    pubkey: Pubkey,
}

/// Configuration for creating a VaultSigner.
#[derive(Clone)]
pub struct VaultSignerConfig {
    pub vault_addr: String,
    pub token: String,
    pub key_name: String,
    pub pubkey: String,
    pub http_client_config: Option<HttpClientConfig>,
}

impl std::fmt::Debug for VaultSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("pubkey", &self.pubkey)
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
    /// * `vault_addr` - Vault server address (e.g., "https://vault.example.com")
    /// * `token` - Vault authentication token
    /// * `key_name` - Vault key name in transit engine
    /// * `pubkey` - Base58-encoded public key
    pub fn new(
        vault_addr: String,
        token: String,
        key_name: String,
        pubkey: String,
    ) -> Result<Self, SignerError> {
        Self::from_config(VaultSignerConfig {
            vault_addr,
            token,
            key_name,
            pubkey,
            http_client_config: None,
        })
    }

    /// Creates a new Vault signer from a configuration object.
    pub fn from_config(config: VaultSignerConfig) -> Result<Self, SignerError> {
        let http_client_config = config.http_client_config.unwrap_or_default();
        let client = http_client_config.build_client()?;

        Self::with_client(
            client,
            config.vault_addr,
            config.token,
            config.key_name,
            config.pubkey,
        )
    }

    /// Creates a Vault signer from a caller-built [`reqwest::Client`].
    ///
    /// Use this when you need control over TLS configuration, proxies,
    /// timeouts, or other client-level settings that `HttpClientConfig`
    /// does not expose — for example, trusting a self-signed CA via
    /// `Client::builder().add_root_certificate(..)` when talking to a
    /// development Vault instance.
    ///
    /// The caller is responsible for whatever security posture the
    /// supplied client carries (HTTPS-only, cert pinning, redirect policy,
    /// etc.); this constructor does not enforce `https_only` and does not
    /// replace the client's redirect policy. Requests carry `X-Vault-Token`,
    /// so a client that follows redirects replays it to the redirect target.
    ///
    /// To avoid pulling `reqwest` into your own dependency tree at a
    /// version that may diverge from `solana-keychain`'s, prefer
    /// constructing the client via the re-exported
    /// [`solana_keychain::vault::reqwest`] module.
    ///
    /// # Arguments
    ///
    /// * `client` - A fully-built reqwest `Client`.
    /// * `vault_addr` - Vault server address (e.g., "https://vault.example.com")
    /// * `token` - Vault authentication token
    /// * `key_name` - Vault key name in transit engine
    /// * `pubkey` - Base58-encoded public key
    pub fn with_client(
        client: Client,
        vault_addr: String,
        token: String,
        key_name: String,
        pubkey: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::try_from(
            bs58::decode(&pubkey)
                .into_vec()
                .map_err(|e| {
                    SignerError::InvalidPublicKey(format!(
                        "Failed to decode base58 public key: {e}"
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key bytes: {e}")))?;

        Ok(Self {
            client: Arc::new(client),
            vault_addr,
            token,
            key_name,
            pubkey,
        })
    }

    async fn sign_bytes(&self, serialized: &[u8]) -> Result<Signature, SignerError> {
        let url = format!("{}/v1/transit/sign/{}", self.vault_addr, self.key_name);

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
        verify_or_reject(&sig, &self.pubkey, serialized)?;

        Ok(sig)
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut VersionedTransaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message.serialize()).await?;

        TransactionUtil::add_signature_to_transaction(transaction, &self.pubkey, signature)?;

        Ok((
            TransactionUtil::serialize_transaction(transaction)?,
            signature,
        ))
    }
}

#[async_trait::async_trait]
impl SolanaSigner for VaultSigner {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
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
        let url = format!("{}/v1/transit/keys/{}", self.vault_addr, self.key_name);

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

        let body: serde_json::Value = match response.json().await {
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
