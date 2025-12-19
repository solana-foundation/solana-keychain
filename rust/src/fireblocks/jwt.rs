//! Fireblocks JWT authentication helper

use crate::error::SignerError;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Serialize)]
struct FireblocksClaims {
    uri: String,
    nonce: String,
    iat: i64,
    exp: i64,
    sub: String,
    #[serde(rename = "bodyHash")]
    body_hash: String,
}

/// Create a JWT for Fireblocks API authentication
///
/// # Arguments
///
/// * `api_key` - Fireblocks API key (used as subject)
/// * `private_key_pem` - RSA 4096 private key in PEM format
/// * `uri` - API endpoint path (e.g., "/v1/transactions")
/// * `body` - Request body as string (empty string for GET requests)
pub fn create_jwt(
    api_key: &str,
    private_key_pem: &str,
    uri: &str,
    body: &str,
) -> Result<String, SignerError> {
    let now = chrono::Utc::now().timestamp();

    // SHA256 hash of body
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let body_hash = hex::encode(hasher.finalize());

    let claims = FireblocksClaims {
        uri: uri.to_string(),
        nonce: Uuid::new_v4().to_string(),
        iat: now,
        exp: now + 30,
        sub: api_key.to_string(),
        body_hash,
    };

    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to parse RSA key: {_e}");

        SignerError::InvalidPrivateKey("Failed to parse RSA key".to_string())
    })?;

    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, &key).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Failed to create JWT: {_e}");

        SignerError::SigningFailed("Failed to create JWT".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test RSA key for unit tests only (PKCS#8 format required by jsonwebtoken)
    const TEST_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKKw7fHhfK3/Ts
rAqsNCrDsjmyBTHx/AUCOTM+tZph2ZOyDSH9nZO4JkzLrW6Vfk7EZvlP3QjLiXEG
m9qQgAh9sXgp07GicWU5omSILTMdd18yR6aIXVw/YzgjD7EVLRQU6YHc3BYgR8P8
PBbJcxzYrrUDSGEXX2b44cZO72RxIPM+yeY3ZXiztgFQSpfEIKX488/k/PgUHMHK
/04VoL/jiQa5dOs44CmHHT6MbBT1Sb/VR0G1hHtfMSIQCtdvzt+VBZhg7sxm50h/
cT+n0UVOBwEp2IY2x4lzlwOdptZl7P3D1+A2rAbalXg5WO+LVEjx5ym++XbCGyvU
rlH+ILOPAgMBAAECggEAXio3F5J/N4YgITqzD+mOf69cc0A7NsCRnqsA5PUWbvw2
cIjwa55BZ1UjkPz7lJML4iwqdNn51j/yzsa6Q3L3QYBvfV/2jbiuku1CUTFobRGk
XBmGhl6h8H5o79/HthrUjzcCP1qdzbRPo4Vjgbpl1cFuW5STcJ0Fq+gRg8O6b3w7
A2843mcF9EA9ZFjXpn+VtpzLe4nHVRZFYXvXSlfdYc6WQbThnLLiLQYsVMqhYQAU
I4c9hfgasfgZ6iCV5hMK2ZPX45+/OVQzjh4+I8zlvNWp2cKNoEhMHU2G/In11yBF
wHGRuvbwx9Wc4Okqq+GvfTO0jCAinAQQu8C+eIcNcQKBgQDo9dzw2cNsJmaUvaL5
I7gEtbPdr+CTgVjGoVUIlGeI0OBHt1DJEwczS2tycScE9SUDLdmegYA8ubHsAs/6
PFEJ+779h9/IDzL3Fe9Zp1fiQgWOKF1uCS7+b8QwFMhh2u0OLWmI1rdFmqX2KCPf
AfD/Pvp6bgapXTN1EoB3LQ/4PwKBgQDeKZeJMk9CZzWFe+m5x2yzJBK62ZvKzyjZ
Y3IeK75V0xG+Y7ZAb0zTXPkgBpBiQOqdFRgt6bp/S/6Tq/OXfeV9xVURSz4zRtCR
lRoONL8ZSl0h4VptEjXrYfBnH2j4gtjhnTATJZBp0rYrExbz0jVbQtRzPLs+k3+p
TuZA8+XwsQKBgCocn8buJpR7UJncugQ9f7tiOVR+waMIg8rMSTnW0ex6jcCJE9J1
XRzZql+ysrIDuqAbfrZXhJ31l4Mpcv0yQBgE6R6dnEdm7/iYf37+cDWXZ7et9k24
3UTjYVyrtRlzYNzqOqSg49pyPUQFN47NpAoQEWlmUE/3aCDmqlBg1f0zAoGAamv+
HUiuUx7hspnTMp1nYsEq/7ryOErYRJqwtec6fB5p54wYZ/FpGe71n/PFAmwadzj9
pjDKl+QthUvfmnhCkOcQgwJKP4Hys2p7WsbFrDXFO0+aY5lPnvwBj0SqojD798e2
mdVqwmafwS6Z1h6iVJ9E6hbzk1xQ0SfsgLzVL2ECgYBN6fJ99og4fkp4iA5C31TB
UKlH64yqwxFu4vuVMqBOpGPkdsLNGhE/vpdP7yYxC/MP+v8ow/sCa40Ely20Yqqa
znT9Ik5JV4eRXyRG9iwllKvcrmczFDIuxFmXPff4G9nmyB9fLQfSM0gD+yDR05Hx
p6B5CCtpBPgD01Vm+bT/JQ==
-----END PRIVATE KEY-----"#;

    #[test]
    fn test_create_jwt() {
        let result = create_jwt(
            "test-api-key",
            TEST_RSA_KEY,
            "/v1/transactions",
            r#"{"test": "body"}"#,
        );

        assert!(result.is_ok());
        let jwt = result.unwrap();
        // JWT should have 3 parts separated by dots
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn test_create_jwt_invalid_key() {
        let result = create_jwt(
            "test-api-key",
            "invalid-key",
            "/v1/transactions",
            r#"{"test": "body"}"#,
        );

        assert!(result.is_err());
    }
}
