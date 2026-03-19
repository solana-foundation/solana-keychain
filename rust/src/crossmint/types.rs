use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletResponse {
    pub chain_type: String,
    #[serde(rename = "type")]
    pub wallet_type: String,
    pub address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionRequest {
    pub params: CreateTransactionParams,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTransactionParams {
    pub transaction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub on_chain: Option<OnChainData>,
    #[serde(default)]
    pub approvals: Option<Approvals>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnChainData {
    #[serde(default)]
    pub transaction: Option<String>,
    #[serde(default)]
    pub tx_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approvals {
    #[serde(default)]
    pub pending: Vec<PendingApproval>,
    #[serde(default)]
    pub submitted: Vec<SubmittedApproval>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmittedApproval {
    #[serde(default)]
    pub signature: Option<String>,
}
