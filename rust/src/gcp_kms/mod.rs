//! Google Cloud KMS signer integration using EdDSA (Ed25519) signing

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction, SolanaSigner};
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
        let client = KeyManagementService::builder().build().await.map_err(|e| {
            SignerError::RemoteApiError(format!("Failed to create KMS client: {e}"))
        })?;

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
        // GCP KMS AsymmetricSign with EC_SIGN_ED25519 takes raw data directly
        // because it operates in PureEdDSA mode
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

                SignerError::RemoteApiError("GCP KMS Sign operation failed".to_string())
            })?;

        // Extract signature from response
        let signature_bytes = response.signature.as_ref();

        if signature_bytes.is_empty() {
            return Err(SignerError::SigningFailed(
                "No signature in GCP KMS response".to_string(),
            ));
        }

        // Ed25519 signatures are 64 bytes
        if signature_bytes.len() != 64 {
            return Err(SignerError::SigningFailed(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            )));
        }

        let sig_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed("Failed to convert signature bytes".to_string())
        })?;

        let sig = Signature::from(sig_bytes);

        if !sig.verify(&self.public_key.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Signature verification failed — the returned signature does not match the public key".to_string(),
            ));
        }

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
            Ok(public_key) => {
                // Verify the algorithm is EC_SIGN_ED25519
                public_key.algorithm == CryptoKeyVersionAlgorithm::EcSignEd25519
            }
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

#[cfg(test)]
mod tests;
