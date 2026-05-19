//! Dfns User Action Signing authentication flow. For more details, see https://docs.dfns.co/api-reference/auth/signing-flows#asymetric-keys-signing-flow

use crate::dfns::types::{
    CredentialAssertion, KeyAssertion, UserActionInitRequest, UserActionInitResponse,
    UserActionResponse, UserActionSignRequest,
};
use crate::error::SignerError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::ed25519::SignatureEncoding as _;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::Signer as _;

/// Perform the Dfns User Action Signing flow for a mutating API request.
///
/// Returns the `userAction` token to include as `x-dfns-useraction` header.
#[allow(clippy::too_many_arguments)]
pub async fn sign_user_action(
    client: &reqwest::Client,
    api_base_url: &str,
    auth_token: &str,
    cred_id: &str,
    private_key_pem: &str,
    http_method: &str,
    http_path: &str,
    body: &str,
) -> Result<String, SignerError> {
    // Request a challenge
    let init_url = format!("{}/auth/action/init", api_base_url);
    let init_request = UserActionInitRequest {
        user_action_payload: body.to_string(),
        user_action_http_method: http_method.to_string(),
        user_action_http_path: http_path.to_string(),
        user_action_server_kind: "Api".to_string(),
    };

    let response = client
        .post(&init_url)
        .header("Authorization", format!("Bearer {}", auth_token))
        .header("Content-Type", "application/json")
        .json(&init_request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();

        #[cfg(feature = "unsafe-debug")]
        {
            let error_text = response.text().await.unwrap_or_default();
            log::error!("Dfns auth/action/init error - status: {status}, response: {error_text}");
        }

        #[cfg(not(feature = "unsafe-debug"))]
        log::error!("Dfns auth/action/init error - status: {status}");

        return Err(SignerError::RemoteApiError(format!(
            "User action init failed with status {status}"
        )));
    }

    let challenge: UserActionInitResponse = response.json().await.map_err(|e| {
        SignerError::SerializationError(format!("Failed to parse action init response: {e}"))
    })?;

    // Verify credential is allowed
    let allowed = challenge
        .allow_credentials
        .key
        .iter()
        .any(|c| c.id == cred_id);
    if !allowed {
        return Err(SignerError::ConfigError(format!(
            "Credential {cred_id} not in allowed credentials"
        )));
    }

    // Sign the challenge
    let client_data = serde_json::json!({
        "type": "key.get",
        "challenge": challenge.challenge,
    });
    let client_data_bytes = client_data.to_string().into_bytes();

    let signature_bytes = sign_challenge(private_key_pem, &client_data_bytes)?;

    let client_data_b64 = URL_SAFE_NO_PAD.encode(&client_data_bytes);
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

    // Submit the signed challenge
    let sign_url = format!("{}/auth/action", api_base_url);
    let sign_request = UserActionSignRequest {
        challenge_identifier: challenge.challenge_identifier,
        first_factor: KeyAssertion {
            kind: "Key".to_string(),
            credential_assertion: CredentialAssertion {
                cred_id: cred_id.to_string(),
                client_data: client_data_b64,
                signature: signature_b64,
            },
        },
    };

    let response = client
        .post(&sign_url)
        .header("Authorization", format!("Bearer {}", auth_token))
        .header("Content-Type", "application/json")
        .json(&sign_request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();

        #[cfg(feature = "unsafe-debug")]
        {
            let error_text = response.text().await.unwrap_or_default();
            log::error!("Dfns auth/action error - status: {status}, response: {error_text}");
        }

        #[cfg(not(feature = "unsafe-debug"))]
        log::error!("Dfns auth/action error - status: {status}");

        return Err(SignerError::RemoteApiError(format!(
            "User action sign failed with status {status}"
        )));
    }

    let action_response: UserActionResponse = response.json().await.map_err(|e| {
        SignerError::SerializationError(format!("Failed to parse action response: {e}"))
    })?;

    Ok(action_response.user_action)
}

/// Sign challenge data with an Ed25519, ECDSA/P256, or RSA private key in PEM format.
fn sign_challenge(private_key_pem: &str, data: &[u8]) -> Result<Vec<u8>, SignerError> {
    // Try Ed25519 (PKCS#8)
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(private_key_pem) {
        return Ok(key.sign(data).to_bytes().to_vec());
    }
    // Try P256/ECDSA (PKCS#8). DER-encoded are expected for ECDSA signatures
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(private_key_pem) {
        let sig: p256::ecdsa::Signature = key.sign(data);
        return Ok(sig.to_der().as_bytes().to_vec());
    }
    // Try P256/ECDSA (SEC1). DER-encoded are expected for ECDSA signatures
    if let Ok(secret) = p256::SecretKey::from_sec1_pem(private_key_pem) {
        let key = p256::ecdsa::SigningKey::from(secret);
        let sig: p256::ecdsa::Signature = key.sign(data);
        return Ok(sig.to_der().as_bytes().to_vec());
    }
    // Try RSA (PKCS#8)
    if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem) {
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);
        let sig = signing_key.sign(data);
        return Ok(sig.to_vec());
    }
    Err(SignerError::InvalidPrivateKey(
        "Unsupported PEM key type (expected Ed25519, P256, or RSA)".into(),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Ed25519 test key in PKCS#8 PEM format
    pub const TEST_ED25519_PEM: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikUmifl1yiWd+IiYyoHBD\n",
        "-----END PRIVATE KEY-----"
    );

    // P256/ECDSA test key in PKCS#8 PEM format
    const TEST_P256_PEM: &str = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n",
        "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n",
        "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n",
        "-----END PRIVATE KEY-----"
    );

    // P256/ECDSA test key in SEC1 PEM format (`BEGIN EC PRIVATE KEY`)
    // Generated with: openssl ecparam -name prime256v1 -genkey -noout
    const TEST_P256_SEC1_PEM: &str = concat!(
        "-----BEGIN EC PRIVATE KEY-----\n",
        "MHcCAQEEIGa93+PpxzDlIywW+Al/cpIAGzLKwGwIDWpgwrJ+ht9ZoAoGCCqGSM49\n",
        "AwEHoUQDQgAE0Mi+Kw78tyVMPAGb6a6Nwn/yiz65gKVBS+nT171vqgLzoHwf51iU\n",
        "TLWfftn3ZyCvKLzTN5pd1Up982TKelcbFw==\n",
        "-----END EC PRIVATE KEY-----"
    );

    // RSA-2048 test key in PKCS#8 PEM format
    const TEST_RSA_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
    fn test_sign_challenge_ed25519() {
        let data = b"test challenge data";
        let result = sign_challenge(TEST_ED25519_PEM, data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_sign_challenge_p256() {
        let data = b"test challenge data";
        let result = sign_challenge(TEST_P256_PEM, data);
        assert!(result.is_ok());
        // DER-encoded ECDSA signatures (typically 70-72 bytes)
        let sig = result.unwrap();
        assert!(
            sig.len() >= 68 && sig.len() <= 72,
            "DER sig len: {}",
            sig.len()
        );
        assert_eq!(sig[0], 0x30, "DER SEQUENCE tag");
    }

    #[test]
    fn test_sign_challenge_p256_sec1() {
        let data = b"test challenge data";
        let result = sign_challenge(TEST_P256_SEC1_PEM, data);
        assert!(result.is_ok());
        let sig = result.unwrap();
        assert!(
            sig.len() >= 68 && sig.len() <= 72,
            "DER sig len: {}",
            sig.len()
        );
        assert_eq!(sig[0], 0x30, "DER SEQUENCE tag");
    }

    #[test]
    fn test_sign_challenge_rsa() {
        let data = b"test challenge data";
        let result = sign_challenge(TEST_RSA_PEM, data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 256);
    }

    #[test]
    fn test_sign_challenge_invalid_key() {
        let result = sign_challenge("not-a-pem-key", b"test");
        assert!(result.is_err());
    }
}
