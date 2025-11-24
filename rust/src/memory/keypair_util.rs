//! Utility functions for parsing private keys in multiple formats

use crate::error::SignerError;
use crate::sdk_adapter::{keypair_from_bytes, Keypair};
use std::fs;

const PRIVATE_KEY_LENGTH: usize = 64;

/// Utility functions for parsing private keys in multiple formats
pub struct KeypairUtil;

impl KeypairUtil {
    /// Creates a new keypair from a private key string that can be in multiple formats:
    /// - Base58 encoded string (current format)
    /// - U8Array format: "[0, 1, 2, ...]"
    /// - File path to a JSON keypair file
    pub fn from_private_key_string(private_key: &str) -> Result<Keypair, SignerError> {
        // Try to parse as a file path first
        if let Ok(file_content) = fs::read_to_string(private_key) {
            return Self::from_json_keypair(&file_content);
        }

        // Try to parse as U8Array format
        if private_key.trim().starts_with('[') && private_key.trim().ends_with(']') {
            return Self::from_u8_array_string(private_key);
        }

        // Default to base58 format (with proper error handling)
        Self::from_base58_safe(private_key)
    }

    /// Creates a new keypair from a base58-encoded private key string with proper error handling
    pub fn from_base58_safe(private_key: &str) -> Result<Keypair, SignerError> {
        // Try to decode as base58 first
        let decoded = bs58::decode(private_key)
            .into_vec()
            .map_err(|e| SignerError::InvalidPrivateKey(format!("Invalid base58 string: {e}")))?;

        if decoded.len() != PRIVATE_KEY_LENGTH {
            return Err(SignerError::InvalidPrivateKey(format!(
                "Invalid private key length: expected {} bytes, got {}",
                PRIVATE_KEY_LENGTH,
                decoded.len()
            )));
        }

        let keypair = keypair_from_bytes(&decoded[..]).map_err(|e| {
            SignerError::InvalidPrivateKey(format!("Invalid private key bytes: {e}"))
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
                if byte_array.len() != PRIVATE_KEY_LENGTH {
                    return Err(SignerError::InvalidPrivateKey(format!(
                        "Private key must be exactly {} bytes, got {}",
                        PRIVATE_KEY_LENGTH,
                        byte_array.len()
                    )));
                }
                keypair_from_bytes(&byte_array[..]).map_err(|e| {
                    SignerError::InvalidPrivateKey(format!("Invalid private key bytes: {e}"))
                })
            }
            Err(e) => Err(SignerError::InvalidPrivateKey(format!(
                "Failed to parse U8Array: {e}"
            ))),
        }
    }

    /// Creates a new keypair from a JSON keypair file content
    pub fn from_json_keypair(json_content: &str) -> Result<Keypair, SignerError> {
        // Try to parse as a simple JSON array first
        if let Ok(byte_array) = serde_json::from_str::<Vec<u8>>(json_content) {
            if byte_array.len() != PRIVATE_KEY_LENGTH {
                return Err(SignerError::InvalidPrivateKey(format!(
                    "JSON keypair must be exactly {} bytes, got {}",
                    PRIVATE_KEY_LENGTH,
                    byte_array.len()
                )));
            }
            return keypair_from_bytes(&byte_array[..]).map_err(|e| {
                SignerError::InvalidPrivateKey(format!("Invalid private key bytes: {e}"))
            });
        }

        Err(SignerError::InvalidPrivateKey(
            "Invalid JSON keypair format. Expected a JSON array of 64 bytes".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk_adapter::keypair_pubkey;

    const TEST_KEYPAIR_BYTES: &str = "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]";
    const TEST_KEYPAIR_BASE58: &str =
        "pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1";
    const TEST_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

    #[test]
    fn test_from_u8_array_string() {
        let result = KeypairUtil::from_u8_array_string(TEST_KEYPAIR_BYTES);
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair_pubkey(&keypair).to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_from_u8_array_invalid_length() {
        let too_short = "[1,2,3]";
        let result = KeypairUtil::from_u8_array_string(too_short);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_u8_array_invalid_format() {
        let invalid = "[not,a,number]";
        let result = KeypairUtil::from_u8_array_string(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_u8_array_empty() {
        let empty = "[]";
        let result = KeypairUtil::from_u8_array_string(empty);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_keypair() {
        let json = TEST_KEYPAIR_BYTES;
        let result = KeypairUtil::from_json_keypair(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_json_keypair_invalid() {
        let invalid_json = "{\"not\": \"an array\"}";
        let result = KeypairUtil::from_json_keypair(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_private_key_string_base58() {
        let result = KeypairUtil::from_private_key_string(TEST_KEYPAIR_BASE58);
        assert!(result.is_ok());
        assert_eq!(keypair_pubkey(&result.unwrap()).to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_from_private_key_string_u8_array() {
        let result = KeypairUtil::from_private_key_string(TEST_KEYPAIR_BYTES);
        assert!(result.is_ok());
        assert_eq!(keypair_pubkey(&result.unwrap()).to_string(), TEST_PUBKEY);
    }

    #[test]
    fn test_from_private_key_string_invalid() {
        let result = KeypairUtil::from_private_key_string("clearly-not-a-valid-key");
        assert!(result.is_err());
    }
}
