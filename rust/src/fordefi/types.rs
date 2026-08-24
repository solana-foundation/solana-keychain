//! Fordefi API types

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared enums
// ---------------------------------------------------------------------------

/// Solana chain identifier used by native Solana signing mode.
#[derive(Clone, Debug, Serialize)]
pub enum SolanaChainUniqueId {
    #[serde(rename = "solana_devnet")]
    SolanaDevnet,
    #[serde(rename = "solana_mainnet")]
    SolanaMainnet,
}

impl SolanaChainUniqueId {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::SolanaDevnet => "solana_devnet",
            Self::SolanaMainnet => "solana_mainnet",
        }
    }
}

/// Controls whether Fordefi broadcasts a native Solana transaction after signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FordefiPushMode {
    /// Fordefi modifies, signs, and broadcasts the transaction.
    Auto,
    /// Fordefi modifies and signs the transaction, leaving broadcast to the caller.
    Manual,
}

/// Priority fee level for native Solana transactions.
#[derive(Clone, Debug, Serialize)]
pub enum FordefiPriorityLevel {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
}

/// Fee configuration for native Solana transactions.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type")]
pub enum FordefiSolanaFee {
    #[serde(rename = "custom")]
    Custom {
        #[serde(skip_serializing_if = "Option::is_none")]
        unit_price: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        priority_fee: Option<String>,
    },
    #[serde(rename = "priority")]
    Priority {
        priority_level: FordefiPriorityLevel,
    },
}

// ---------------------------------------------------------------------------
// Black box signing
// ---------------------------------------------------------------------------

/// Request body for POST /api/v1/transactions (black_box vault).
///
/// Black box vaults sign raw bytes via EdDSA and return a pure Ed25519 signature
/// without any chain-specific semantics.
#[derive(Serialize)]
pub struct BlackBoxSignatureRequest {
    pub vault_id: String,
    pub signer_type: &'static str,
    pub sign_mode: &'static str,
    #[serde(rename = "type")]
    pub tx_type: &'static str,
    pub details: BlackBoxDetails,
}

/// Details for a black_box_signature request.
#[derive(Serialize)]
pub struct BlackBoxDetails {
    pub format: &'static str,
    pub hash_binary: String,
}

// ---------------------------------------------------------------------------
// Native Solana signing (recommended)
// ---------------------------------------------------------------------------

/// Request body for native Solana transaction signing via
/// `solana_serialized_transaction_message`.
///
/// Fordefi signs the serialized transaction message and either pushes it on-chain
/// or returns it for caller-managed broadcasting.
#[derive(Serialize)]
pub struct SolanaTransactionRequest {
    pub vault_id: String,
    pub signer_type: &'static str,
    pub sign_mode: &'static str,
    #[serde(rename = "type")]
    pub tx_type: &'static str,
    pub details: SolanaTransactionDetails,
}

/// Details for a native Solana transaction request.
#[derive(Serialize)]
pub struct SolanaTransactionDetails {
    #[serde(rename = "type")]
    pub detail_type: &'static str,
    pub chain: SolanaChainUniqueId,
    pub data: String,
    pub push_mode: FordefiPushMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<FordefiSolanaFee>,
}

/// Request body for native Solana message signing via `solana_message`.
///
/// Fordefi signs a personal message (non-pushable).
#[derive(Serialize)]
pub struct SolanaMessageRequest {
    pub vault_id: String,
    pub signer_type: &'static str,
    pub sign_mode: &'static str,
    #[serde(rename = "type")]
    pub tx_type: &'static str,
    pub details: SolanaMessageDetails,
}

/// Details for a native Solana message request.
#[derive(Serialize)]
pub struct SolanaMessageDetails {
    #[serde(rename = "type")]
    pub detail_type: &'static str,
    pub chain: SolanaChainUniqueId,
    pub raw_data: String,
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Response from POST /api/v1/transactions
#[derive(Deserialize)]
pub struct CreateTransactionResponse {
    pub id: String,
}

/// A signature entry returned in the polling response.
#[derive(Deserialize)]
pub struct FordefiSignatureEntry {
    pub data: String,
}

/// Response from GET /api/v1/transactions/{id} (polling)
#[derive(Deserialize)]
pub struct TransactionStatusResponse {
    pub state: String,
    pub signatures: Option<Vec<FordefiSignatureEntry>>,
    /// Base64-encoded signed wire transaction (present on solana_transaction responses).
    pub raw_transaction: Option<String>,
}

/// Response from GET /api/v1/vaults/{id}.
///
/// Chain-specific vaults expose `address`, while black-box vaults expose
/// `public_key_compressed` instead.
#[derive(Deserialize)]
pub struct VaultResponse {
    /// Solana base58 address bound to a chain-specific vault.
    pub address: Option<String>,
    #[allow(dead_code)]
    pub id: String,
    /// Base64-encoded compressed public key exposed by a black-box vault.
    pub public_key_compressed: Option<String>,
    /// Vault type, such as `black_box`.
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub vault_type: Option<String>,
}

#[cfg(test)]
mod tests;
