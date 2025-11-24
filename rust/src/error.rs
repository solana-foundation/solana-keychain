//! Error types for signer operations

use std::fmt;
use thiserror::Error;

/// Errors that can occur during signing operations
#[derive(Error)]
pub enum SignerError {
    /// Invalid private key format
    #[error("Invalid private key format: {0}")]
    InvalidPrivateKey(String),

    /// Invalid public key format
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Remote API error (Vault, Privy, Turnkey)
    #[error("Remote API error: {0}")]
    RemoteApiError(String),

    /// HTTP request error
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Signer not available
    #[error("Signer not available: {0}")]
    NotAvailable(String),

    /// IO error (file operations)
    #[error("IO error: {0}")]
    IoError(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
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

#[cfg(any(feature = "vault", feature = "privy", feature = "turnkey"))]
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
            SignerError::Other(_) => write!(f, "SignerError::Other([REDACTED])"),
        }
    }
}
