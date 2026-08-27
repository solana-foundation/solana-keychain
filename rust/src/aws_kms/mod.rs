//! AWS KMS signer integration using EdDSA (Ed25519) signing

use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SignedTransaction, TransactionSigner};
use crate::{error::SignerError, traits::SolanaSigner, transaction_util::TransactionUtil};
use aws_config::Region;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client as KmsClient,
};
use std::str::FromStr;

use crate::signature_util::{signature_from_bytes, verify_or_reject};

const AWS_KMS_SIGNING_ALGORITHM: &str = "ED25519_SHA_512";
const AWS_KMS_KEY_SPEC: &str = "ECC_NIST_EDWARDS25519";
const AWS_KMS_KEY_USAGE: &str = "SIGN_VERIFY";

/// AWS KMS-based signer using EdDSA (Ed25519) signing
///
/// # Example
///
/// ```rust,ignore
/// use solana_keychain::AwsKmsSigner;
///
/// let signer = AwsKmsSigner::new(
///     "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string(),
///     "YourSolanaPublicKeyBase58".to_string(),
///     Some("us-east-1".to_string()),
/// ).await?;
/// ```
#[derive(Clone)]
pub struct AwsKmsSigner {
    client: KmsClient,
    key_id: String,
    public_key: Pubkey,
}

/// Configuration for creating an AwsKmsSigner.
#[derive(Clone)]
pub struct AwsKmsSignerConfig {
    pub key_id: String,
    pub public_key: String,
    pub region: Option<String>,
}

impl std::fmt::Debug for AwsKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsSigner")
            .field("key_id", &self.key_id)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl AwsKmsSigner {
    /// Create a new AwsKmsSigner
    ///
    /// # Arguments
    ///
    /// * `key_id` - AWS KMS key ID or ARN (must be an ECC_NIST_EDWARDS25519 key)
    /// * `public_key` - Solana public key (base58-encoded)
    /// * `region` - Optional AWS region (defaults to default region from AWS config)
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid.
    pub async fn new(
        key_id: String,
        public_key: String,
        region: Option<String>,
    ) -> Result<Self, SignerError> {
        Self::from_config(AwsKmsSignerConfig {
            key_id,
            public_key,
            region,
        })
        .await
    }

    /// Create a new AwsKmsSigner from a configuration object.
    pub async fn from_config(config: AwsKmsSignerConfig) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&config.public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        // Build AWS config
        let mut config_builder = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Some(region_str) = &config.region {
            config_builder = config_builder.region(Region::new(region_str.clone()));
        }

        let aws_config = config_builder.load().await;
        let client = KmsClient::new(&aws_config);

        Ok(Self {
            client,
            key_id: config.key_id,
            public_key: pubkey,
        })
    }

    /// Create a new AwsKmsSigner with an existing KMS client
    ///
    /// This is useful for testing or when you want to configure the client yourself.
    ///
    /// # Arguments
    ///
    /// * `client` - Pre-configured AWS KMS client
    /// * `key_id` - AWS KMS key ID or ARN (must be an ECC_NIST_EDWARDS25519 key)
    /// * `public_key` - Solana public key (base58-encoded)
    pub fn with_client(
        client: KmsClient,
        key_id: String,
        public_key: String,
    ) -> Result<Self, SignerError> {
        let pubkey = Pubkey::from_str(&public_key)
            .map_err(|e| SignerError::InvalidPublicKey(format!("Invalid public key: {e}")))?;

        Ok(Self {
            client,
            key_id,
            public_key: pubkey,
        })
    }

    /// Get the key ID
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Sign message bytes using AWS KMS EdDSA signing
    async fn sign_bytes(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // The SDK may not have a typed enum variant yet since Ed25519 support was added
        // in November 2025; from() creates an "Unknown" variant that still works.
        let signing_algorithm = SigningAlgorithmSpec::from(AWS_KMS_SIGNING_ALGORITHM);

        let response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(signing_algorithm)
            .send()
            .await
            .map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("AWS KMS Sign operation failed: {_e:?}");

                SignerError::RemoteApiError("AWS KMS Sign operation failed".to_string())
            })?;

        let signature_blob = response.signature().ok_or_else(|| {
            SignerError::SigningFailed("No signature in AWS KMS response".to_string())
        })?;

        let sig = signature_from_bytes(signature_blob.as_ref())?;
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

    /// Check if AWS KMS is available and the key is accessible
    async fn check_availability(&self) -> bool {
        // Try to describe the key as a health check
        let result = self.client.describe_key().key_id(&self.key_id).send().await;

        match result {
            Ok(response) => {
                let Some(key_metadata) = response.key_metadata() else {
                    return false;
                };

                let Some(key_spec) = key_metadata.key_spec() else {
                    return false;
                };

                // The SDK may represent these values as typed enums or Unknown("...") variants.
                if key_spec.as_str() != AWS_KMS_KEY_SPEC {
                    return false;
                }

                if !key_metadata.enabled() {
                    return false;
                }

                let Some(key_usage) = key_metadata.key_usage() else {
                    return false;
                };

                key_usage.as_str() == AWS_KMS_KEY_USAGE
            }
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for AwsKmsSigner {
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
impl TransactionSigner for AwsKmsSigner {
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
