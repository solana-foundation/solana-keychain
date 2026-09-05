//! Ledger hardware-wallet integration tests.
//!
//! Unlike the other backends, Ledger has no remote API or credentials — it
//! needs a **physical device** plugged in, unlocked, and running the Solana
//! app. These tests are therefore gated behind `integration-tests` *and* skip
//! themselves at runtime when no device is connected, so they are safe to leave
//! in the normal `integration-tests` matrix.
//!
//! Run manually with a device attached:
//! ```bash
//! just rust-test-ledger
//! ```

#[cfg(feature = "ledger")]
#[cfg(test)]
mod tests {
    use crate::ledger::LedgerSigner;
    use crate::traits::{SolanaSigner, TransactionSigner};

    /// Connect, or skip when there is genuinely no device.
    ///
    /// Skipping is deliberate: CI has no Ledger and these tests must not fail
    /// there. But it is only legitimate when no device is attached. If one *is*
    /// attached and we still cannot connect — locked, wrong app, another process
    /// holding it — that is an operator problem, and panicking is the honest
    /// outcome. Reporting it as a pass is how a locked Gen5 previously made this
    /// whole suite look green while testing nothing.
    fn try_connect() -> Option<LedgerSigner> {
        match LedgerSigner::connect(None, false, None) {
            Ok(signer) => Some(signer),
            Err(e) if !LedgerSigner::is_attached() => {
                eprintln!(
                    "skipping Ledger hardware test -- no device attached: {}",
                    e.detail_string()
                );
                None
            }
            Err(e) => panic!(
                "a Ledger is attached but unusable, so this is a real failure \
                 rather than a skip: {}",
                e.detail_string()
            ),
        }
    }

    /// Regression test: connect, drop, reconnect — repeatedly, in one process.
    ///
    /// This is the shape that used to abort the whole test binary with SIGTRAP
    /// inside macOS's HID stack. Dropping a signer returned while its device
    /// actor still owned the `hidapi` handle, so the next `connect` initialised
    /// HID concurrently with that teardown. Every operation passed in isolation,
    /// which is precisely why it read as a flaky test instead of a lifecycle bug.
    ///
    /// It needs no button press, and a crash here fails the run rather than
    /// producing a confusing partial pass.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_reconnect_cycle_does_not_crash() {
        let Some(first) = try_connect() else { return };
        let pubkey = first.pubkey();
        drop(first);

        for round in 0..3 {
            let signer = LedgerSigner::connect(None, false, None).unwrap_or_else(|e| {
                panic!(
                    "reconnect {round} failed after a clean drop: {}",
                    e.detail_string()
                )
            });
            assert_eq!(
                signer.pubkey(),
                pubkey,
                "the same device must derive the same key across reconnects"
            );
            drop(signer);
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_pubkey_and_availability() {
        let Some(signer) = try_connect() else { return };
        assert!(
            signer.is_available().await,
            "device should report available"
        );
        // A real Solana pubkey is 32 bytes and never the zero address.
        assert_ne!(signer.pubkey(), Default::default());
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_sign_offchain_message() {
        let Some(signer) = try_connect() else { return };
        // Requires a press on the device to approve.
        let message = b"solana-keychain ledger integration test";
        let signature = signer
            .sign_message(message)
            .await
            .expect("device should sign the off-chain message");
        assert_eq!(signature.as_ref().len(), 64);
        // `sign_message` signs the *envelope*, not the raw bytes, so verify
        // against the envelope the backend built. Note this is deliberately not
        // `solana_offchain_message`'s serialization: that layout is rejected by
        // the device, which is what made this path fail on hardware for months.
        // See `ledger_offchain_envelope`.
        let envelope =
            crate::ledger::ledger_offchain_envelope(&signer.pubkey(), message).expect("envelope");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), &envelope),
            "signature must verify against the envelope the device signed"
        );
        // Guard against a regression to the previous, rejected layout: the
        // signature must NOT verify against the raw payload.
        assert!(
            !signature.verify(&signer.pubkey().to_bytes(), message),
            "signature covers the envelope, not the raw payload"
        );
    }

    // ── Operator-driven regressions ──
    //
    // These need a human to do something to the device mid-test, so they are
    // `#[ignore]`d and driven by `scripts/ledger-hardware-runbook.sh`. Running
    // them unattended would hang or fail meaninglessly.

    /// F-14: declining a transaction must not destroy the session.
    ///
    /// The defect this pins: `with_session` dropped the session on any error,
    /// `UserRejected` included, and nothing but `connect` could rebuild one. So
    /// declining once made every later signature fail with "no Ledger session;
    /// connect first" on a device that was working perfectly.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must reject on the device; run via the hardware runbook"]
    async fn test_ledger_rejection_does_not_kill_the_session() {
        use crate::traits::TransactionSigner;
        let Some(signer) = try_connect() else {
            panic!("this test needs a device")
        };
        let mut tx = crate::test_util::create_test_transaction(&signer.pubkey());

        eprintln!("\n>>> REJECT this transaction on the device.\n");
        let rejected = signer.sign_transaction(&mut tx).await;
        assert!(
            matches!(rejected, Err(crate::error::SignerError::UserRejected(_))),
            "expected a rejection, got: {rejected:?}"
        );

        eprintln!("\n>>> Now APPROVE this one. It must not fail with 'no Ledger session'.\n");
        let mut tx2 = crate::test_util::create_test_transaction(&signer.pubkey());
        signer
            .sign_transaction(&mut tx2)
            .await
            .expect("the session must survive a rejection");
    }

    /// F-14: the same signer instance must recover from an unplug/replug.
    ///
    /// A transport error correctly drops the session; before the re-establish
    /// logic, nothing could ever rebuild it, so the signer stayed dead even once
    /// the device was back.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must unplug the device; run via the hardware runbook"]
    async fn test_ledger_signer_survives_unplug_replug() {
        use crate::traits::TransactionSigner;
        let Some(signer) = try_connect() else {
            panic!("this test needs a device")
        };
        let mut tx = crate::test_util::create_test_transaction(&signer.pubkey());
        eprintln!("\n>>> APPROVE this first transaction.\n");
        signer.sign_transaction(&mut tx).await.expect("first sign");

        eprintln!("\n>>> Now UNPLUG the device, plug it back in, unlock it, open the Solana app.");
        eprintln!(">>> Waiting 45s. Do NOT construct a new signer; this is the same instance.\n");
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;

        let mut tx2 = crate::test_util::create_test_transaction(&signer.pubkey());
        eprintln!("\n>>> APPROVE this second transaction.\n");
        signer
            .sign_transaction(&mut tx2)
            .await
            .expect("the same signer must re-establish its session after a replug");
    }

    /// F-1: a probe must not hang behind an unconfirmed signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must leave a prompt unanswered; run via the hardware runbook"]
    async fn test_ledger_probe_returns_while_a_signature_is_pending() {
        use crate::traits::TransactionSigner;
        use std::sync::Arc;
        let Some(signer) = try_connect() else {
            panic!("this test needs a device")
        };
        let signer = Arc::new(signer);
        let mut tx = crate::test_util::create_test_transaction(&signer.pubkey());

        eprintln!("\n>>> Do NOT touch the device. Leave the prompt unanswered.\n");
        let signing = {
            let signer = Arc::clone(&signer);
            tokio::spawn(async move { signer.sign_transaction(&mut tx).await })
        };
        // Let the command reach the device and raise the busy flag.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let start = std::time::Instant::now();
        let available = signer.is_available().await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < crate::ledger::OPS_TIMEOUT + std::time::Duration::from_secs(2),
            "a probe must return within its own tier deadline, took {elapsed:?}"
        );
        assert!(
            !available,
            "a device mid-prompt must report unavailable, not block"
        );

        let start = std::time::Instant::now();
        let _ = crate::ledger::LedgerSigner::is_attached();
        assert!(
            start.elapsed() < crate::ledger::OPS_TIMEOUT + std::time::Duration::from_secs(2),
            "is_attached must not hang behind a prompt"
        );

        // And a second *signing* request must be refused in milliseconds
        // rather than queueing behind the prompt. This is the observable that
        // the atomic claim exists to provide: before it, admission was
        // check-then-act and this call would have waited out its whole signing
        // timeout.
        let mut tx2 = crate::test_util::create_test_transaction(&signer.pubkey());
        let start = std::time::Instant::now();
        let refused = signer.sign_transaction(&mut tx2).await;
        let elapsed = start.elapsed();
        assert!(
            refused.is_err(),
            "a second signature during a pending prompt must be refused"
        );
        let detail = refused.unwrap_err().detail_string();
        assert!(
            detail.contains("busy with another operation"),
            "must be the busy error, got: {detail}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "must fail fast, took {elapsed:?}"
        );
        eprintln!("second signer refused in {elapsed:?}: {detail}");

        eprintln!("\n>>> You may now REJECT the pending prompt to finish.\n");
        let _ = signing.await;
    }

    /// N6: a non-ASCII off-chain message needs blind signing enabled.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must toggle blind signing; run via the hardware runbook"]
    async fn test_ledger_non_ascii_offchain_message_needs_blind_signing() {
        let Some(signer) = try_connect() else {
            panic!("this test needs a device")
        };
        // Valid UTF-8 that is not printable ASCII, so the envelope carries
        // format 1 (LimitedUtf8), which the app gates behind blind signing.
        let payload = "café ☕ solana-keychain".as_bytes();
        eprintln!("\n>>> Run this FIRST with blind signing DISABLED (expect a failure),");
        eprintln!(">>> then again with it ENABLED (expect a prompt to approve).\n");
        match signer.sign_message(payload).await {
            Ok(sig) => {
                eprintln!(
                    "signed: blind signing was enabled. signature len {}",
                    sig.as_ref().len()
                );
            }
            Err(e) => {
                eprintln!(
                    "refused, as expected with blind signing disabled: {}",
                    e.detail_string()
                );
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_sign_transaction() {
        use crate::test_util::create_test_transaction;

        let Some(signer) = try_connect() else { return };
        let mut tx = create_test_transaction(&signer.pubkey());
        // Requires a press on the device to approve.
        let result = signer
            .sign_transaction(&mut tx)
            .await
            .expect("device should sign the transaction");
        let (_serialized, signature) = result.into_signed_transaction();
        assert_eq!(signature.as_ref().len(), 64);
        assert_eq!(tx.signatures[0], signature);
    }
}
