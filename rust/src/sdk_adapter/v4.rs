//! Adapter for Solana SDK v4.x

// Re-export core types from solana-sdk v4
pub use solana_compute_budget_interface_v3::ID as COMPUTE_BUDGET_PROGRAM_ID;
#[allow(unused_imports)]
pub use solana_sdk_v4::hash::Hash;
#[allow(unused_imports)]
pub use solana_sdk_v4::instruction::{AccountMeta, Instruction};
#[allow(unused_imports)]
pub use solana_sdk_v4::message::compiled_instruction::CompiledInstruction;
#[allow(unused_imports)]
pub use solana_sdk_v4::message::v0::Message as V0Message;
#[allow(unused_imports)]
pub use solana_sdk_v4::message::{Message, MessageHeader, VersionedMessage};
pub use solana_sdk_v4::pubkey::Pubkey;
pub use solana_sdk_v4::signature::{Keypair, Signature};
#[allow(unused_imports)]
pub use solana_sdk_v4::signer::Signer;
#[allow(unused_imports)]
pub use solana_sdk_v4::transaction::Transaction;
pub use solana_sdk_v4::transaction::VersionedTransaction;

/// Parse a keypair from bytes (v4 adapter)
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair, String> {
    Keypair::try_from(bytes).map_err(|e| format!("Invalid keypair bytes: {}", e))
}

/// Get the public key from a keypair (v4 adapter)
pub fn keypair_pubkey(keypair: &Keypair) -> Pubkey {
    keypair.pubkey()
}

/// Derive a keypair from a 32-byte seed (v4 adapter)
#[allow(dead_code)]
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair, String> {
    solana_sdk_v4::signer::keypair::keypair_from_seed(seed).map_err(|e| e.to_string())
}

/// Sign a message with a keypair (v4 adapter)
pub fn keypair_sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign_message(message)
}
