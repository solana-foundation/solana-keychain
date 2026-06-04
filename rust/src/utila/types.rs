use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletResponse {
    pub wallet: Wallet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wallet {
    pub solana_details: Option<SolanaDetails>,
}

#[derive(Deserialize)]
pub struct SolanaDetails {
    pub address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitiateTransactionRequest {
    pub details: InitiateTransactionDetails,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub designated_signers: Vec<String>,
}

#[derive(Serialize)]
pub struct InitiateTransactionDetails {
    #[serde(rename = "solanaSerializedTransaction")]
    pub solana_serialized_transaction: SolanaSerializedTransaction,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolanaSerializedTransaction {
    pub network: String,
    pub raw_transaction: String,
    pub publish: bool,
    pub replace_blockhash: bool,
    pub try_replace_blockhash: bool,
}

#[derive(Deserialize)]
pub struct TransactionEnvelope {
    pub transaction: UtilaTransaction,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UtilaTransaction {
    pub name: String,
    pub state: TransactionState,
    pub solana_transaction: Option<UtilaSolanaTransaction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionState {
    AwaitingApproval,
    AwaitingAmlPolicyCheck,
    DeclinedByAmlPolicy,
    AwaitingPolicyCheck,
    AwaitingSignature,
    Signed,
    AwaitingPublish,
    Published,
    Mined,
    MinedFailed,
    Failed,
    Declined,
    Replaced,
    Canceled,
    Dropped,
    Confirmed,
    Expired,
    #[serde(other)]
    Unknown,
}

impl TransactionState {
    pub fn is_terminal_failure(self) -> bool {
        matches!(
            self,
            TransactionState::DeclinedByAmlPolicy
                | TransactionState::MinedFailed
                | TransactionState::Failed
                | TransactionState::Declined
                | TransactionState::Replaced
                | TransactionState::Canceled
                | TransactionState::Dropped
                | TransactionState::Expired
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UtilaSolanaTransaction {
    pub raw_transaction: Option<String>,
}
