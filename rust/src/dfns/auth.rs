//! Dfns User Action Signing authentication flow. For more details, see https://docs.dfns.co/api-reference/auth/signing-flows#asymetric-keys-signing-flow

use crate::dfns::types::{
    CredentialAssertion, KeyAssertion, UserActionInitRequest, UserActionInitResponse,
    UserActionResponse, UserActionSignRequest,
};
use crate::error::SignerError;
use crate::remote_util::parse_json_response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey as _;
use rsa::signature::SignatureEncoding as _;

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

    let challenge: UserActionInitResponse =
        parse_json_response(response, "Dfns auth/action/init").await?;

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

    let action_response: UserActionResponse =
        parse_json_response(response, "Dfns auth/action").await?;

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
pub(crate) mod tests;
