//! Google Cloud KMS signer integration using EdDSA (Ed25519) signing

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::signature_util::{signature_from_bytes, verify_or_reject};
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner, TransactionSigner};
use crate::transaction_util::TransactionUtil;
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key_version::CryptoKeyVersionAlgorithm;
use std::str::FromStr;

/// GCP KMS-based signer using EdDSA (Ed25519) signing
///
/// # Example
///
/// ```rust,ignore
/// use solana_keychain::GcpKmsSigner;
///
/// let signer = GcpKmsSigner::new(
///     "projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1".to_string(),
///     "YourSolanaPublicKeyBase58".to_string(),
/// ).await?;
/// ```
#[derive(Clone)]
pub struct GcpKmsSigner {
    client: KeyManagementService,
    key_name: String,
    public_key: Pubkey,
}

/// Configuration for creating a GcpKmsSigner.
#[derive(Clone)]
pub struct GcpKmsSignerConfig {
    pub key_name: String,
    pub public_key: String,
}

impl std::fmt::Debug for GcpKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsSigner")
            .field("key_name", &self.key_name)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl GcpKmsSigner {
    /// Create a new GcpKmsSigner
    ///
    /// # Arguments
    ///
    /// * `key_name` - Full resource name of the crypto key version
    /// * `public_key` - Solana public key (base58-encoded)
    pub async fn new(key_name: String, public_key: String) -> Result<Self, SignerError> {
        Self::from_config(GcpKmsSignerConfig {
            key_name,
            public_key,
        })
        .await
    }

    /// Create a new GcpKmsSigner from a configuration object.
    pub async fn from_config(config: GcpKmsSignerConfig) -> Result<Self, SignerError> {
        let client = KeyManagementService::builder()
            .build()
            .await
            .map_err(|e| SignerError::remote_api(format!("Failed to create KMS client: {e}")))?;

        Self::with_client(client, config.key_name, config.public_key)
    }

    /// Create a new GcpKmsSigner with a pre-configured client
    pub fn with_client(
        client: KeyManagementService,
        key_name: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            client,
            key_name,
            public_key: pubkey,
        })
    }

    /// Get the GCP KMS key name
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Sign message bytes using GCP KMS EdDSA signing
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // GCP KMS AsymmetricSign takes raw data directly (PureEdDSA mode).
        let response = self
            .client
            .asymmetric_sign()
            .set_name(&self.key_name)
            .set_data(message.to_vec())
            .send()
            .await
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("GCP KMS Sign operation failed: {_e:?}");

                SignerError::remote_api("GCP KMS Sign operation failed".to_string())
            })?;

        let sig = signature_from_bytes(response.signature.as_ref())?;
        verify_or_reject(&sig, &self.public_key, message)?;

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

    /// Check if GCP KMS is available and the key is accessible
    async fn check_availability(&self) -> bool {
        // Try to get the public key as a health check
        let result = self
            .client
            .get_public_key()
            .set_name(&self.key_name)
            .send()
            .await;

        match result {
            Ok(public_key) => public_key.algorithm == CryptoKeyVersionAlgorithm::EcSignEd25519,
            Err(_e) => {
                #[cfg(feature = "unsafe-debug")]
                log::error!("GCP KMS availability check failed: {_e:?}");

                false
            }
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for GcpKmsSigner {
    fn pubkey(&self) -> Pubkey {
        self.public_key
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        self.check_availability().await
    }
}

#[async_trait::async_trait]
impl TransactionSigner for GcpKmsSigner {
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

#[cfg(test)]
mod tests;
