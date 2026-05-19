use crate::sdk_adapter::{self, Hash, Pubkey, Transaction};
use std::error::Error;

#[cfg(feature = "sdk-v2")]
use litesvm::LiteSVM;
#[cfg(feature = "sdk-v3")]
use litesvm_v3::LiteSVM;

pub async fn start_litesvm(payer: &Pubkey) -> Result<LiteSVM, Box<dyn Error>> {
    let mut svm = LiteSVM::new()
        .with_sysvars()
        .with_default_programs()
        .with_sigverify(true);

    svm.airdrop(payer, 1_000_000_000).unwrap();

    Ok(svm)
}

pub async fn get_latest_blockhash(litesvm: &LiteSVM) -> Result<Hash, Box<dyn Error>> {
    Ok(litesvm.latest_blockhash())
}

pub async fn simulate_transaction(
    litesvm: &LiteSVM,
    transaction: &Transaction,
) -> Result<(), Box<dyn Error>> {
    let tx_bytes = bincode::serialize(transaction).expect("Failed to serialize transaction");

    let tx_for_litesvm: sdk_adapter::Transaction =
        bincode::deserialize(&tx_bytes).expect("Failed to deserialize transaction");

    let result = litesvm.simulate_transaction(tx_for_litesvm);

    assert!(result.is_ok(), "Failed to simulate transaction");

    Ok(())
}
