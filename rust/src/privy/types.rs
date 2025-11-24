//! Privy API types and error handling

use serde::{Deserialize, Serialize};

// API request/response types for Privy
#[derive(Serialize)]
pub struct SignMessageRequest {
    pub method: &'static str,
    pub params: SignMessageParams,
}

#[derive(Serialize)]
pub struct SignMessageParams {
    pub message: String,
    pub encoding: &'static str,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SignMessageResponse {
    pub method: String,
    pub data: SignMessageData,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct SignMessageData {
    pub signature: String,
    pub encoding: String,
}

// Wallet info response
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct WalletResponse {
    pub id: String,
    pub address: String,
    pub chain_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_client_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hd_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_signers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}
