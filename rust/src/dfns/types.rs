//! Dfns API types for request/response serialization

use serde::{Deserialize, Serialize};

// ── Wallet API ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetWalletResponse {
    #[allow(dead_code)]
    pub id: String,
    pub status: String,
    pub signing_key: SigningKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKey {
    pub id: String,
    pub scheme: String,
    pub curve: String,
    pub public_key: String,
}

// ── Signature API ───────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
pub enum GenerateSignatureRequest {
    Message {
        message: String,
    },
    Transaction {
        transaction: String,
        #[serde(rename = "blockchainKind")]
        blockchain_kind: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateSignatureResponse {
    #[allow(dead_code)]
    pub id: String,
    pub status: String,
    pub signature: Option<SignatureComponents>,
    #[allow(dead_code)]
    pub signed_data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureComponents {
    pub r: String,
    pub s: String,
}

// ── User Action Signing ─────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionInitRequest {
    pub user_action_payload: String,
    pub user_action_http_method: String,
    pub user_action_http_path: String,
    pub user_action_server_kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionInitResponse {
    pub challenge: String,
    pub challenge_identifier: String,
    pub allow_credentials: AllowCredentials,
}

#[derive(Debug, Deserialize)]
pub struct AllowCredentials {
    pub key: Vec<AllowCredential>,
}

#[derive(Debug, Deserialize)]
pub struct AllowCredential {
    pub id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionSignRequest {
    pub challenge_identifier: String,
    pub first_factor: KeyAssertion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAssertion {
    pub kind: String,
    pub credential_assertion: CredentialAssertion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialAssertion {
    pub cred_id: String,
    pub client_data: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionResponse {
    pub user_action: String,
}
