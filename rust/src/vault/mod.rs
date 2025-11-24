//! HashiCorp Vault signer integration

use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::SignedTransaction;
use crate::{error::SignerError, traits::SolanaSigner, transaction_util::TransactionUtil};
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

impl std::fmt::Debug for VaultSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl VaultSigner {
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
        let client = Client::new();

        let pubkey = Pubkey::try_from(
            bs58::decode(pubkey)
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

        if !response.status().is_success() {
            let status = response.status();

            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            #[cfg(feature = "unsafe-debug")]
            log::error!("Vault API error - status: {status}, response: {error_text}");

            #[cfg(not(feature = "unsafe-debug"))]
            log::error!("Vault API error - status: {status}");

            return Err(SignerError::RemoteApiError(format!(
                "Vault API error {}",
                status
            )));
        }

        let result: serde_json::Value = response.json().await.map_err(|_| {
            SignerError::SerializationError("Failed to parse Vault response".to_string())
        })?;

        let signature_b64 = result["data"]["signature"].as_str().ok_or_else(|| {
            SignerError::RemoteApiError("No signature in Vault response".to_string())
        })?;

        // Remove the version prefix (e.g., "vault:v1:") if present
        let signature_b64 = signature_b64
            .strip_prefix("vault:v1:")
            .unwrap_or(signature_b64);

        let sig_bytes = STANDARD.decode(signature_b64).map_err(|_| {
            SignerError::SerializationError("Failed to decode signature".to_string())
        })?;

        Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| SignerError::SigningFailed("Invalid signature format".to_string()))
    }

    async fn sign_and_serialize(
        &self,
        transaction: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        let signature = self.sign_bytes(&transaction.message_data()).await?;

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
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn sign_partial_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignedTransaction, SignerError> {
        self.sign_and_serialize(tx).await
    }

    async fn is_available(&self) -> bool {
        // Check if we can read the key metadata as a health check
        let url = format!("{}/v1/transit/keys/{}", self.vault_addr, self.key_name);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VAULT_ADDR: &str = "http://127.0.0.1:8200";
    const TEST_VAULT_TOKEN: &str = "test-token";
    const TEST_KEY_NAME: &str = "test-key";
    const TEST_PUBKEY: &str = "2vfDxWYbhRt7GXiRYKf1Dr5Z8y7zVQCSERbDTKyBaAqQ";

    fn create_test_signer() -> VaultSigner {
        VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            TEST_PUBKEY.to_string(),
        )
        .expect("Failed to create test signer")
    }

    #[test]
    fn test_create_vault_signer() {
        let signer = VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            TEST_PUBKEY.to_string(),
        );
        assert!(signer.is_ok());
    }

    #[test]
    fn test_invalid_pubkey() {
        let signer = VaultSigner::new(
            TEST_VAULT_ADDR.to_string(),
            TEST_VAULT_TOKEN.to_string(),
            TEST_KEY_NAME.to_string(),
            "invalid-pubkey".to_string(),
        );
        assert!(signer.is_err());
    }

    #[test]
    fn test_pubkey() {
        let signer = create_test_signer();
        let pubkey = signer.pubkey();
        assert_eq!(pubkey.to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_debug_impl() {
        let signer = create_test_signer();
        let debug_str = format!("{:?}", signer);
        assert!(debug_str.contains("VaultSigner"));
        assert!(debug_str.contains("pubkey"));
    }
}
