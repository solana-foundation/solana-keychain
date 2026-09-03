use crate::sdk_adapter::{Hash, Pubkey, VersionedTransaction};
use crate::transaction_util::serialize_wire_transaction;
use std::error::Error;

#[cfg(feature = "sdk-v2")]
use litesvm::LiteSVM;
#[cfg(feature = "sdk-v3")]
use litesvm_v3::LiteSVM;
// No litesvm-v4: no released litesvm version is compatible with solana-sdk
// >=4.1 yet (litesvm 0.13.0 needs solana-instruction =3.2.0, solana-sdk 4.1
// needs ^3.5.0; litesvm 0.16.0 needs solana-signature ~3.4.1, solana-sdk 4.1
// needs ^3.5.0 — see the agave-feature-set-pin comment in Cargo.toml). This
// module, and every test that calls it under sdk-v4, is unavailable until
// litesvm publishes a compatible release; re-add `litesvm_v4::LiteSVM` here
// once it does. Production sdk-v4 usage is unaffected: dev-dependencies never
// propagate to downstream consumers of this crate.
#[cfg(feature = "sdk-v4")]
compile_error!(
    "litesvm-based tests are unavailable under sdk-v4 pending a compatible \
     litesvm release (see src/tests/litesvm_util.rs); build without sdk-v4 \
     to run this test suite, or without --tests to use the library"
);

use crate::sdk_adapter::VersionedTransaction as LiteSvmTransaction;

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
    transaction: &VersionedTransaction,
) -> Result<(), Box<dyn Error>> {
    let tx_bytes =
        serialize_wire_transaction(transaction).expect("Failed to serialize transaction");

    let tx_for_litesvm: LiteSvmTransaction =
        bincode::deserialize(&tx_bytes).expect("Failed to deserialize transaction");

    let result = litesvm.simulate_transaction(tx_for_litesvm);

    assert!(result.is_ok(), "Failed to simulate transaction");

    Ok(())
}
