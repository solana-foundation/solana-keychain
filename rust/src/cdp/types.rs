use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct SignTransactionResponse {
    #[serde(rename = "signedTransaction")]
    pub(super) signed_transaction: String,
}

#[derive(Deserialize)]
pub(super) struct SignMessageResponse {
    pub(super) signature: String,
}
