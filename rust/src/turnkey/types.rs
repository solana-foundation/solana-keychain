//! Turnkey API types

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    #[serde(rename = "type")]
    pub activity_type: String,
    pub timestamp_ms: String,
    pub organization_id: String,
    pub parameters: SignParameters,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignParameters {
    pub sign_with: String,
    pub payload: String,
    pub encoding: String,
    pub hash_function: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityResponse {
    pub activity: Activity,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub status: Option<String>,
    pub result: Option<ActivityResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTransactionRequest {
    #[serde(rename = "type")]
    pub activity_type: String,
    pub timestamp_ms: String,
    pub organization_id: String,
    pub parameters: SignTransactionParameters,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTransactionParameters {
    pub sign_with: String,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub unsigned_transaction: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityResult {
    pub sign_raw_payload_result: Option<SignResult>,
    pub sign_transaction_result: Option<SignTransactionResult>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTransactionResult {
    pub signed_transaction: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    pub r: String,
    pub s: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoAmIRequest {
    pub organization_id: String,
}
