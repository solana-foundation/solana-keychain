//! Para API types

use serde::{Deserialize, Serialize};

/// Wallet info response from GET /v1/wallets/{walletId}
#[derive(Deserialize)]
pub struct WalletResponse {
    #[allow(dead_code)]
    pub id: String,
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub wallet_type: String,
    pub status: String,
}

/// Request body for POST /v1/wallets/{walletId}/sign-raw
#[derive(Serialize)]
pub struct SignRawRequest {
    pub data: String,
    pub encoding: &'static str,
}

/// Response from POST /v1/wallets/{walletId}/sign-raw
#[derive(Deserialize)]
pub struct SignRawResponse {
    pub signature: Option<String>,
}
