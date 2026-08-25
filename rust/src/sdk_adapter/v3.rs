//! Adapter for Solana SDK v3.x

// Re-export core types from solana-sdk v3
#[allow(unused_imports)]
pub use solana_sdk_v3::hash::Hash;
#[allow(unused_imports)]
pub use solana_sdk_v3::instruction::{AccountMeta, Instruction};
#[allow(unused_imports)]
pub use solana_sdk_v3::message::compiled_instruction::CompiledInstruction;
#[allow(unused_imports)]
pub use solana_sdk_v3::message::v0::Message as V0Message;
#[allow(unused_imports)]
pub use solana_sdk_v3::message::{Message, MessageHeader, VersionedMessage};
pub use solana_sdk_v3::pubkey::Pubkey;
pub use solana_sdk_v3::signature::{Keypair, Signature};
#[allow(unused_imports)]
pub use solana_sdk_v3::signer::Signer;
#[allow(unused_imports)]
pub use solana_sdk_v3::transaction::Transaction;
pub use solana_sdk_v3::transaction::VersionedTransaction;

/// Parse a keypair from bytes (v3 adapter)
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair, String> {
    Keypair::try_from(bytes).map_err(|e| format!("Invalid keypair bytes: {}", e))
}

/// Get the public key from a keypair (v3 adapter)
pub fn keypair_pubkey(keypair: &Keypair) -> Pubkey {
    keypair.pubkey()
}

/// Derive a keypair from a 32-byte seed (v3 adapter)
#[allow(dead_code)]
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair, String> {
    solana_sdk_v3::signer::keypair::keypair_from_seed(seed).map_err(|e| e.to_string())
}

/// Sign a message with a keypair (v3 adapter)
pub fn keypair_sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign_message(message)
}

/// The Compute Budget program ID, `ComputeBudget111111111111111111111111111111`.
///
/// Declared locally rather than pulled from `solana-compute-budget-interface`:
/// the ID is fixed and consensus-critical, and depending on that crate would add
/// it to every consumer's tree, including those enabling only `memory`.
#[allow(dead_code)]
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");
