//! Error types for signer operations

use std::fmt;
use thiserror::Error;

use crate::sdk_adapter::Signature;

/// Errors that can occur during signing operations
#[derive(Error)]
pub enum SignerError {
    /// Invalid private key format
    #[error("Invalid private key format")]
    InvalidPrivateKey(String),

    /// Invalid public key format
    #[error("Invalid public key")]
    InvalidPublicKey(String),

    /// Signing operation failed
    #[error("Signing failed")]
    SigningFailed(String),

    /// Remote API error (any remote signer backend: Vault, Privy, Turnkey, Fireblocks, AWS/GCP KMS, Dfns, Crossmint, CDP, Para, Openfort, Utila, Fordefi)
    ///
    /// `provider_tx_id` carries the provider's id for a request it accepted but
    /// did not finish, so a caller who gives up waiting can still look the
    /// request up. It is `None` for every failure that left no such request
    /// behind. Nothing was broadcast: a backend that may have put a transaction
    /// on chain reports [`SignerError::BroadcastUnconfirmed`] instead.
    #[error("Remote API error")]
    RemoteApiError {
        detail: String,
        provider_tx_id: Option<String>,
    },

    /// HTTP request error
    #[error("HTTP request failed")]
    HttpError(String),

    /// Serialization/deserialization error
    #[error("Serialization error")]
    SerializationError(String),

    /// Configuration error
    #[error("Configuration error")]
    ConfigError(String),

    /// Signer not available
    #[error("Signer not available")]
    NotAvailable(String),

    /// The signing request was rejected by the user (e.g. declined on a
    /// hardware-wallet device screen).
    #[error("Request rejected by user")]
    UserRejected(String),

    /// IO error (file operations)
    #[error("IO error")]
    IoError(String),

    /// The provider or a caller-supplied sender may have executed the transaction,
    /// but the outcome could not be confirmed. Retrying blindly risks a duplicate
    /// spend; reconcile the provider id or transaction signature first.
    ///
    /// `transaction_signature` identifies the completed transaction passed to a
    /// caller-managed sender. Provider-managed broadcasts leave it `None`.
    #[error("Broadcast unconfirmed; the provider may have executed the transaction (provider transaction id: {})", provider_tx_id.as_deref().unwrap_or("unknown"))]
    BroadcastUnconfirmed {
        provider_tx_id: Option<String>,
        provider_status: Option<u16>,
        idempotency_key: Option<String>,
        transaction_signature: Option<Box<Signature>>,
        detail: String,
    },

    /// Generic error
    #[error("Signer error")]
    Other(String),
}

impl SignerError {
    /// A remote API failure that left no pending provider request behind.
    pub fn remote_api(detail: impl Into<String>) -> Self {
        Self::RemoteApiError {
            detail: detail.into(),
            provider_tx_id: None,
        }
    }

    pub(crate) fn detail_string(&self) -> String {
        match self {
            Self::InvalidPrivateKey(detail)
            | Self::InvalidPublicKey(detail)
            | Self::SigningFailed(detail)
            | Self::HttpError(detail)
            | Self::SerializationError(detail)
            | Self::ConfigError(detail)
            | Self::NotAvailable(detail)
            | Self::UserRejected(detail)
            | Self::IoError(detail)
            | Self::Other(detail) => detail.clone(),
            Self::RemoteApiError { detail, .. } | Self::BroadcastUnconfirmed { detail, .. } => {
                detail.clone()
            }
        }
    }
}

impl From<std::io::Error> for SignerError {
    fn from(err: std::io::Error) -> Self {
        SignerError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for SignerError {
    fn from(err: serde_json::Error) -> Self {
        SignerError::SerializationError(err.to_string())
    }
}

#[cfg(feature = "_remote")]
impl From<reqwest::Error> for SignerError {
    fn from(err: reqwest::Error) -> Self {
        SignerError::HttpError(err.to_string())
    }
}

// Custom Debug implementation to prevent leaking sensitive information
impl fmt::Debug for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::InvalidPrivateKey(_) => {
                write!(f, "SignerError::InvalidPrivateKey([REDACTED])")
            }
            SignerError::InvalidPublicKey(_) => {
                write!(f, "SignerError::InvalidPublicKey([REDACTED])")
            }
            SignerError::SigningFailed(_) => write!(f, "SignerError::SigningFailed([REDACTED])"),
            SignerError::RemoteApiError { provider_tx_id, .. } => match provider_tx_id {
                Some(id) => write!(
                    f,
                    "SignerError::RemoteApiError(provider_tx_id: {id}, [REDACTED])"
                ),
                None => write!(f, "SignerError::RemoteApiError([REDACTED])"),
            },
            SignerError::HttpError(_) => write!(f, "SignerError::HttpError([REDACTED])"),
            SignerError::SerializationError(_) => {
                write!(f, "SignerError::SerializationError([REDACTED])")
            }
            SignerError::ConfigError(_) => write!(f, "SignerError::ConfigError([REDACTED])"),
            SignerError::NotAvailable(_) => write!(f, "SignerError::NotAvailable([REDACTED])"),
            SignerError::UserRejected(_) => write!(f, "SignerError::UserRejected([REDACTED])"),
            SignerError::IoError(_) => write!(f, "SignerError::IoError([REDACTED])"),
            SignerError::BroadcastUnconfirmed {
                provider_tx_id,
                idempotency_key,
                ..
            } => {
                write!(
                    f,
                    "SignerError::BroadcastUnconfirmed(provider_tx_id: {}, idempotency_key: {}, [REDACTED])",
                    provider_tx_id.as_deref().unwrap_or("unknown"),
                    idempotency_key.as_deref().unwrap_or("unknown")
                )
            }
            SignerError::Other(_) => write!(f, "SignerError::Other([REDACTED])"),
        }
    }
}

#[cfg(test)]
mod tests;
