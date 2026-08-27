//! Utility functions for parsing private keys in multiple formats

use crate::error::SignerError;
use crate::sdk_adapter::{keypair_from_bytes, Keypair};
use std::fs;
use zeroize::Zeroizing;

const PRIVATE_KEY_LENGTH: usize = 64;

/// Utility functions for parsing private keys in multiple formats
pub struct KeypairUtil;

impl KeypairUtil {
    /// Creates a new keypair from a private key string that can be in multiple formats:
    /// - Base58 encoded string (current format)
    /// - U8Array format: "[0, 1, 2, ...]"
    pub fn from_private_key_string(private_key: &str) -> Result<Keypair, SignerError> {
        if private_key.trim().starts_with('[') && private_key.trim().ends_with(']') {
            return Self::from_u8_array_string(private_key);
        }

        Self::from_base58_safe(private_key)
    }

    /// Creates a new keypair by reading a JSON keypair file from disk.
    pub fn from_private_key_file(path: &str) -> Result<Keypair, SignerError> {
        let file_content_raw = fs::read_to_string(path).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to read private key file from disk: {_e}");
            SignerError::IoError("Failed to read private key file".to_string())
        })?;
        let file_content = Zeroizing::new(file_content_raw);
        Self::from_json_keypair(&file_content)
    }

    /// Creates a new keypair from a base58-encoded private key string with proper error handling
    pub fn from_base58_safe(private_key: &str) -> Result<Keypair, SignerError> {
        let decoded = Zeroizing::new(bs58::decode(private_key).into_vec().map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to decode base58 private key: {_e}");
            SignerError::InvalidPrivateKey("Invalid private key format".to_string())
        })?);

        if decoded.len() != PRIVATE_KEY_LENGTH {
            return Err(SignerError::InvalidPrivateKey(format!(
                "Invalid private key length: expected {} bytes, got {}",
                PRIVATE_KEY_LENGTH,
                decoded.len()
            )));
        }

        let keypair = keypair_from_bytes(&decoded[..]).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Failed to build keypair from decoded private key bytes: {_e}");
            SignerError::InvalidPrivateKey("Invalid private key bytes".to_string())
        })?;

        Ok(keypair)
    }

    /// Creates a new keypair from a U8Array format string like "[0, 1, 2, ...]"
    pub fn from_u8_array_string(array_str: &str) -> Result<Keypair, SignerError> {
        let trimmed = array_str.trim();

        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return Err(SignerError::InvalidPrivateKey(
                "U8Array string must start with '[' and end with ']'".to_string(),
            ));
        }

        let inner = &trimmed[1..trimmed.len() - 1];

        if inner.trim().is_empty() {
            return Err(SignerError::InvalidPrivateKey(
                "U8Array string cannot be empty".to_string(),
            ));
        }

        let bytes: Result<Vec<u8>, _> = inner.split(',').map(|s| s.trim().parse::<u8>()).collect();

        match bytes {
            Ok(byte_array) => {
                let byte_array = Zeroizing::new(byte_array);
                if byte_array.len() != PRIVATE_KEY_LENGTH {
                    return Err(SignerError::InvalidPrivateKey(format!(
                        "Private key must be exactly {} bytes, got {}",
                        PRIVATE_KEY_LENGTH,
                        byte_array.len()
                    )));
                }
                keypair_from_bytes(&byte_array[..]).map_err(|_e| {
                    #[cfg(feature = "unsafe-debug")]
                    log::error!("Failed to build keypair from U8Array private key bytes: {_e}");
                    SignerError::InvalidPrivateKey("Invalid private key bytes".to_string())
                })
            }
            Err(_e) => {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to parse U8Array private key: {_e}");
                Err(SignerError::InvalidPrivateKey(
                    "Invalid U8Array private key format".to_string(),
                ))
            }
        }
    }

    /// Creates a new keypair from a JSON keypair file content
    pub fn from_json_keypair(json_content: &str) -> Result<Keypair, SignerError> {
        if let Ok(byte_array) = serde_json::from_str::<Vec<u8>>(json_content) {
            let byte_array = Zeroizing::new(byte_array);
            if byte_array.len() != PRIVATE_KEY_LENGTH {
                return Err(SignerError::InvalidPrivateKey(format!(
                    "JSON keypair must be exactly {} bytes, got {}",
                    PRIVATE_KEY_LENGTH,
                    byte_array.len()
                )));
            }
            return keypair_from_bytes(&byte_array[..]).map_err(|_e| {
                #[cfg(feature = "unsafe-debug")]
                log::error!("Failed to build keypair from JSON private key bytes: {_e}");
                SignerError::InvalidPrivateKey("Invalid private key bytes".to_string())
            });
        }

        Err(SignerError::InvalidPrivateKey(
            "Invalid JSON keypair format. Expected a JSON array of 64 bytes".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests;
