use crate::sdk_adapter::{Hash, Pubkey, Transaction};
use std::error::Error;

#[cfg(feature = "sdk-v2")]
use litesvm::LiteSVM;
#[cfg(feature = "sdk-v3")]
use litesvm_v3::LiteSVM;
#[cfg(feature = "sdk-v4")]
use litesvm_v4::LiteSVM;

// litesvm 0.13 (sdk-v4) exposes simulate_transaction in terms of
// solana-transaction 3.x, while solana-sdk 4.x uses solana-transaction 4.x.
// The bincode wire format is identical across both, so v4 transactions are
// round-tripped through the litesvm-compatible 3.x type. For v2/v3 the
// adapter's own Transaction type already matches the bundled litesvm.
#[cfg(not(feature = "sdk-v4"))]
use crate::sdk_adapter::Transaction as LiteSvmTransaction;
#[cfg(feature = "sdk-v4")]
use solana_transaction_litesvm_v4::Transaction as LiteSvmTransaction;

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

    let tx_for_litesvm: LiteSvmTransaction =
        bincode::deserialize(&tx_bytes).expect("Failed to deserialize transaction");

    let result = litesvm.simulate_transaction(tx_for_litesvm);

    assert!(result.is_ok(), "Failed to simulate transaction");

    Ok(())
}
