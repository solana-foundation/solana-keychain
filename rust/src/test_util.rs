use std::str::FromStr;

use crate::sdk_adapter::{AccountMeta, Hash, Instruction, Message, Pubkey, Transaction};

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

pub fn create_test_transaction(from: &Pubkey) -> Transaction {
    let to = Pubkey::new_unique();
    let instruction = create_transfer_instruction(from, &to, 1_000_000);
    let message = Message::new(&[instruction], Some(from));
    let mut tx = Transaction::new_unsigned(message);
    tx.message.recent_blockhash = Hash::default();
    tx
}
