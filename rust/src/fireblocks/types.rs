//! Fireblocks API types

use serde::{Deserialize, Serialize};

/// Request to create a signing transaction in Fireblocks
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRequest {
    pub asset_id: String,
    pub operation: String,
    pub source: TransactionSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_parameters: Option<ExtraParameters>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub id: String,
}

/// Extra parameters for Fireblocks signing operations
#[derive(Serialize)]
#[serde(untagged)]
pub enum ExtraParameters {
    /// RAW signing operation
    Raw(RawExtraParameters),
    /// PROGRAM_CALL signing operation
    ProgramCall(ProgramCallExtraParameters),
}

/// Extra parameters for RAW signing
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawExtraParameters {
    pub raw_message_data: RawMessageData,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMessageData {
    pub messages: Vec<RawMessage>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMessage {
    pub content: String,
}

/// Extra parameters for PROGRAM_CALL signing
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramCallExtraParameters {
    /// Base64-encoded serialized Solana transaction
    pub program_call_data: String,
}

/// Response from creating a transaction
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionResponse {
    pub id: String,
    #[allow(dead_code)]
    pub status: String,
}

/// Response from getting a transaction (used for polling)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    #[allow(dead_code)]
    pub id: String,
    pub status: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub sub_status: Option<String>,
    #[serde(default)]
    pub signed_messages: Vec<SignedMessage>,
    /// Transaction hash (populated for PROGRAM_CALL after broadcast)
    #[serde(default)]
    pub tx_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedMessage {
    pub signature: SignatureData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureData {
    pub full_sig: String,
}

/// Response from getting vault account addresses (paginated)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAddressesResponse {
    pub addresses: Vec<VaultAddress>,
}

/// A single vault address
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAddress {
    pub address: String,
}
