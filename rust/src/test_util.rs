use std::str::FromStr;

#[cfg(feature = "sdk-v4")]
use crate::sdk_adapter::Signature;
use crate::sdk_adapter::{
    AccountMeta, Hash, Instruction, Message, Pubkey, Transaction, VersionedMessage,
    VersionedTransaction,
};
#[cfg(feature = "sdk-v4")]
use solana_sdk_v4::message::v1::{Message as V1Message, TransactionConfig};

fn create_transfer_instruction(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data: {
            let mut data = vec![2, 0, 0, 0];
            data.extend_from_slice(&lamports.to_le_bytes());
            data
        },
    }
}

pub fn create_test_transaction(from: &Pubkey) -> VersionedTransaction {
    let to = Pubkey::new_unique();
    create_test_transaction_with_recipient(from, &to)
}

pub fn create_test_transaction_with_recipient(from: &Pubkey, to: &Pubkey) -> VersionedTransaction {
    let instruction = create_transfer_instruction(from, to, 1_000_000);
    let message = Message::new(&[instruction], Some(from));
    let mut tx = Transaction::new_unsigned(message);
    tx.message.recent_blockhash = Hash::default();
    tx.into()
}

/// Insert `pubkey` as a second required signer in a legacy test transaction.
pub fn add_required_signer(transaction: &mut VersionedTransaction, pubkey: Pubkey) {
    let VersionedMessage::Legacy(message) = &mut transaction.message else {
        panic!("test helper only mutates legacy messages");
    };
    message.account_keys.insert(1, pubkey);
    message.header.num_required_signatures = 2;
}

/// A v1 test transaction. v1 messages exist only in solana-sdk 4.x, and v1 treats
/// an unset resource limit as zero rather than a default.
#[cfg(feature = "sdk-v4")]
pub fn create_test_v1_transaction(from: &Pubkey) -> VersionedTransaction {
    let to = Pubkey::new_unique();
    let instruction = create_transfer_instruction(from, &to, 1_000_000);
    let config = TransactionConfig::empty()
        .with_compute_unit_limit(30_000)
        .with_loaded_accounts_data_size_limit(65_536);
    let message = V1Message::try_compile_with_config(from, &[instruction], Hash::default(), config)
        .expect("v1 test message should compile");

    VersionedTransaction {
        signatures: vec![Signature::default(); usize::from(message.header.num_required_signatures)],
        message: VersionedMessage::V1(message),
    }
}
