//! Adapter for Solana SDK v2.x

// Re-export core types from solana-sdk v2
#[allow(unused_imports)]
pub use solana_sdk::hash::Hash;
#[allow(unused_imports)]
pub use solana_sdk::instruction::{AccountMeta, Instruction};
#[allow(unused_imports)]
pub use solana_sdk::message::Message;
pub use solana_sdk::pubkey::Pubkey;
pub use solana_sdk::signature::{Keypair, Signature};
pub use solana_sdk::signer::Signer;
pub use solana_sdk::transaction::Transaction;

/// Parse a keypair from bytes (v2 adapter)
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair, String> {
    #[allow(deprecated)]
    Keypair::from_bytes(bytes).map_err(|e| e.to_string())
}

/// Get the public key from a keypair (v2 adapter)
pub fn keypair_pubkey(keypair: &Keypair) -> Pubkey {
    keypair.pubkey()
}

/// Sign a message with a keypair (v2 adapter)
pub fn keypair_sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign_message(message)
}
