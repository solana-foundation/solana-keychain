//! Adapter for Solana SDK v3.x

// Re-export core types from solana-sdk v3
#[allow(unused_imports)]
pub use solana_sdk_v3::hash::Hash;
#[allow(unused_imports)]
pub use solana_sdk_v3::instruction::{AccountMeta, Instruction};
#[allow(unused_imports)]
pub use solana_sdk_v3::message::Message;
pub use solana_sdk_v3::pubkey::Pubkey;
pub use solana_sdk_v3::signature::{Keypair, Signature};
#[allow(unused_imports)]
pub use solana_sdk_v3::signer::Signer;
pub use solana_sdk_v3::transaction::Transaction;

/// Parse a keypair from bytes (v3 adapter)
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair, String> {
    Keypair::try_from(bytes).map_err(|e| format!("Invalid keypair bytes: {}", e))
}

/// Get the public key from a keypair (v3 adapter)
pub fn keypair_pubkey(keypair: &Keypair) -> Pubkey {
    keypair.pubkey()
}

/// Sign a message with a keypair (v3 adapter)
pub fn keypair_sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign_message(message)
}
