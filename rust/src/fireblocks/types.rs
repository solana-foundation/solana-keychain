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
#[serde(untagged)]
pub enum ExtraParameters {
    Raw(RawExtraParameters),
    ProgramCall(ProgramCallExtraParameters),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub id: String,
}

/// Extra parameters for RAW signing
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawExtraParameters {
    pub raw_message_data: RawMessageData,
}

/// Extra parameters for PROGRAM_CALL signing.
///
/// `use_durable_nonce` defaults to `true` on the Fireblocks side, which prepends
/// an `AdvanceNonce` instruction to the submitted message; the signature would
/// then cover different bytes than the caller's transaction.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramCallExtraParameters {
    pub program_call_data: String,
    pub sign_only: bool,
    pub use_durable_nonce: bool,
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
    pub asset_id: Option<String>,
}
