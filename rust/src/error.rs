//! Error types for signer operations

use std::fmt;
use thiserror::Error;

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
    #[error("Remote API error")]
    RemoteApiError(String),

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

    /// IO error (file operations)
    #[error("IO error")]
    IoError(String),

    /// The provider may have executed the transaction, but the outcome could not
    /// be confirmed. Raised by broadcast-managed signers (Fordefi native mode,
    /// Crossmint) for any failure after the provider has accepted the
    /// transaction. Retrying blindly risks a duplicate spend; check the provider
    /// transaction id first.
    ///
    /// Both fields are `None` when the create failed without a usable response:
    /// nothing to check, and the only safe recovery is replaying the identical
    /// bytes.
    #[error("Broadcast unconfirmed; the provider may have executed the transaction (provider transaction id: {})", provider_tx_id.as_deref().unwrap_or("unknown"))]
    BroadcastUnconfirmed {
        provider_tx_id: Option<String>,
        provider_status: Option<u16>,
        detail: String,
    },

    /// Generic error
    #[error("Signer error")]
    Other(String),
}

impl SignerError {
    pub(crate) fn detail_string(&self) -> String {
        match self {
            Self::InvalidPrivateKey(detail)
            | Self::InvalidPublicKey(detail)
            | Self::SigningFailed(detail)
            | Self::RemoteApiError(detail)
            | Self::HttpError(detail)
            | Self::SerializationError(detail)
            | Self::ConfigError(detail)
            | Self::NotAvailable(detail)
            | Self::IoError(detail)
            | Self::Other(detail) => detail.clone(),
            Self::BroadcastUnconfirmed { detail, .. } => detail.clone(),
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

#[cfg(any(
    feature = "vault",
    feature = "privy",
    feature = "turnkey",
    feature = "fireblocks",
    feature = "cdp",
    feature = "dfns",
    feature = "para",
    feature = "crossmint",
    feature = "openfort",
    feature = "utila",
    feature = "fordefi"
))]
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
            SignerError::RemoteApiError(_) => {
                write!(f, "SignerError::RemoteApiError([REDACTED])")
            }
            SignerError::HttpError(_) => write!(f, "SignerError::HttpError([REDACTED])"),
            SignerError::SerializationError(_) => {
                write!(f, "SignerError::SerializationError([REDACTED])")
            }
            SignerError::ConfigError(_) => write!(f, "SignerError::ConfigError([REDACTED])"),
            SignerError::NotAvailable(_) => write!(f, "SignerError::NotAvailable([REDACTED])"),
            SignerError::IoError(_) => write!(f, "SignerError::IoError([REDACTED])"),
            SignerError::BroadcastUnconfirmed { provider_tx_id, .. } => {
                write!(
                    f,
                    "SignerError::BroadcastUnconfirmed(provider_tx_id: {}, [REDACTED])",
                    provider_tx_id.as_deref().unwrap_or("unknown")
                )
            }
            SignerError::Other(_) => write!(f, "SignerError::Other([REDACTED])"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SignerError;

    #[test]
    fn test_display_is_redacted_for_all_variants() {
        let secret = "sensitive-secret-material";
        let cases = [
            SignerError::InvalidPrivateKey(secret.to_string()),
            SignerError::InvalidPublicKey(secret.to_string()),
            SignerError::SigningFailed(secret.to_string()),
            SignerError::RemoteApiError(secret.to_string()),
            SignerError::HttpError(secret.to_string()),
            SignerError::SerializationError(secret.to_string()),
            SignerError::ConfigError(secret.to_string()),
            SignerError::NotAvailable(secret.to_string()),
            SignerError::IoError(secret.to_string()),
            SignerError::Other(secret.to_string()),
            SignerError::BroadcastUnconfirmed {
                provider_tx_id: Some("tx-id".to_string()),
                provider_status: None,
                detail: secret.to_string(),
            },
        ];

        for err in cases {
            let display = format!("{err}");
            assert!(
                !display.contains(secret),
                "display output leaked sensitive content: {display}"
            );
        }
    }

    #[test]
    fn test_display_messages_are_stable_and_generic() {
        assert_eq!(
            format!("{}", SignerError::InvalidPrivateKey("x".to_string())),
            "Invalid private key format"
        );
        assert_eq!(
            format!("{}", SignerError::InvalidPublicKey("x".to_string())),
            "Invalid public key"
        );
        assert_eq!(
            format!("{}", SignerError::SigningFailed("x".to_string())),
            "Signing failed"
        );
        assert_eq!(
            format!("{}", SignerError::RemoteApiError("x".to_string())),
            "Remote API error"
        );
        assert_eq!(
            format!("{}", SignerError::HttpError("x".to_string())),
            "HTTP request failed"
        );
        assert_eq!(
            format!("{}", SignerError::SerializationError("x".to_string())),
            "Serialization error"
        );
        assert_eq!(
            format!("{}", SignerError::ConfigError("x".to_string())),
            "Configuration error"
        );
        assert_eq!(
            format!("{}", SignerError::NotAvailable("x".to_string())),
            "Signer not available"
        );
        assert_eq!(
            format!("{}", SignerError::IoError("x".to_string())),
            "IO error"
        );
        assert_eq!(
            format!("{}", SignerError::Other("x".to_string())),
            "Signer error"
        );
    }

    #[test]
    fn test_broadcast_unconfirmed_surfaces_tx_id_but_not_detail() {
        let err = SignerError::BroadcastUnconfirmed {
            provider_tx_id: Some("provider-tx-123".to_string()),
            provider_status: None,
            detail: "sensitive-detail".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("provider-tx-123"));
        assert!(!display.contains("sensitive-detail"));
        let debug = format!("{err:?}");
        assert!(debug.contains("provider-tx-123"));
        assert!(!debug.contains("sensitive-detail"));
    }
}
