//! Hardware probe for the Solana-app auto-launch path.
//!
//! Run with a Ledger plugged in and **unlocked, sitting on the dashboard with
//! the Solana app closed** — the whole point is to prove the CLI launches the
//! app for the user instead of erroring "open the Solana app".
//!
//! ```sh
//! just rust-ledger-open-app
//! ```
//!
//! Expected: the device prompts to open Solana (confirm on-screen), then this
//! prints the derived address at m/44'/501'/0'. Also try it with the Solana app
//! already open (should be a silent no-op) and with a different app open (should
//! quit to dashboard, then launch Solana).

#[cfg(feature = "ledger")]
fn main() {
    use solana_keychain::ledger::LedgerSigner;

    eprintln!("Connecting to Ledger (auto-launching the Solana app if needed)…");
    match LedgerSigner::connect(None, false, None) {
        Ok(signer) => {
            use solana_keychain::traits::SolanaSigner;
            println!("✓ Solana app is running.");
            println!("  address (m/44'/501'/0'): {}", signer.pubkey());
        }
        Err(e) => {
            eprintln!("✗ connect failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "ledger"))]
fn main() {
    eprintln!("build with --no-default-features --features memory,ledger,sdk-v3");
}
