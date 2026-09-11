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
//!
//! Use that recipe, not a bare `cargo test`. It passes `--test-threads=1`,
//! and it has to: there is one device, one process-wide device actor and one
//! `DeviceClaim`, so tests run in parallel contend for all three. Run in
//! parallel these fail rather than skip, naming the busy state -- which is the
//! honest outcome, since a test that cannot reach the device has not passed.

#[cfg(feature = "ledger")]
#[cfg(test)]
mod tests {
    use crate::ledger::LedgerSigner;
    use crate::traits::{SolanaSigner, TransactionSigner};

    /// Connect, or skip when there is genuinely no device.
    ///
    /// Skip only when the connect error contains [`crate::ledger::NO_DEVICE_DETAIL`].
    /// Any other error means a device is present but unusable (locked, wrong app,
    /// held by another process), which is an operator problem and must fail.
    /// `is_attached()` is not used because it returns `false` for both "cannot tell"
    /// (device mid-command, timed out) and "nothing attached", making it unreliable
    /// to discriminate. Additionally, `is_attached()` re-initializes the HID stack,
    /// and enough of those in one process aborts the test binary on macOS.
    fn try_connect() -> Option<LedgerSigner> {
        let e = match LedgerSigner::connect(None, false, None) {
            Ok(signer) => return Some(signer),
            Err(e) => e,
        };
        let detail = e.detail_string();

        if detail.contains(crate::ledger::NO_DEVICE_DETAIL) {
            eprintln!("skipping Ledger hardware test -- no device attached: {detail}");
            return None;
        }
        panic!(
            "a Ledger is attached but unusable, or the connect could not tell, so this \
             is a real failure rather than a skip: {detail}"
        );
    }

    /// Connect, drop, reconnect repeatedly in one process. On macOS, HID
    /// re-initialisation across thread lifecycles aborts the process with
    /// SIGTRAP unless the device thread is a singleton; single operations
    /// never show it.
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

    /// Declining a transaction is an app-level answer over a healthy
    /// transport, so the session must survive it.
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

    /// The same signer instance must recover from an unplug/replug.
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

    /// N5: the Solana app is launched from the dashboard, not demanded of the
    /// user.
    ///
    /// Set the device up **unlocked, on the dashboard, with the Solana app
    /// closed**. Connecting must launch the app automatically. Also worth running
    /// with the app already open (silent no-op) and with a different app open
    /// (quit to dashboard, then launch).
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must close the Solana app; run via the hardware runbook"]
    async fn test_ledger_integration_open_app() {
        eprintln!("\n>>> Device must be UNLOCKED, on the DASHBOARD, Solana app CLOSED.");
        eprintln!(">>> CONFIRM the open-app prompt when it appears.\n");

        // Deliberately not `try_connect`: this test must fail rather than skip
        // when the auto-launch does not happen, and the whole behaviour under
        // test is the connect itself.
        let signer = LedgerSigner::connect_with(crate::ledger::LedgerConfig::default())
            .unwrap_or_else(|e| {
                panic!(
                    "connect must launch the Solana app from the dashboard rather than \
                     failing: {}",
                    e.detail_string()
                )
            });
        assert_ne!(
            signer.pubkey(),
            Default::default(),
            "a launched app must derive a real address"
        );
        eprintln!(
            "Solana app running; address (m/44'/501'/0'): {}",
            signer.pubkey()
        );
    }

    /// N6: a non-ASCII off-chain message needs blind signing enabled.
    ///
    /// `LEDGER_BLIND_SIGNING` environment variable directs the test:
    /// - `disabled` - device must refuse with blind signing error
    /// - `enabled` - device must sign and signature must verify against envelope
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    #[ignore = "operator must toggle blind signing; run via the hardware runbook"]
    async fn test_ledger_non_ascii_offchain_message_needs_blind_signing() {
        let expectation = std::env::var("LEDGER_BLIND_SIGNING").unwrap_or_default();
        let blind_signing_enabled = match expectation.as_str() {
            "enabled" => true,
            "disabled" => false,
            other => panic!(
                "set LEDGER_BLIND_SIGNING=disabled or =enabled to say how the device is \
                 configured; got {other:?}. `just rust-ledger-evidence` sets it per phase. \
                 Without it this test cannot assert a direction, and a test that passes \
                 either way is how this one previously backed two runbook phases that \
                 could not fail."
            ),
        };

        let Some(signer) = try_connect() else {
            panic!("this test needs a device")
        };
        // Valid UTF-8 that is not printable ASCII, so the envelope carries
        // format 1 (LimitedUtf8), which the app gates behind blind signing.
        let payload = "café ☕ solana-keychain".as_bytes();
        let result = signer.sign_message(payload).await;

        if blind_signing_enabled {
            eprintln!("\n>>> APPROVE the prompt on the device.\n");
            let signature = result.unwrap_or_else(|e| {
                panic!(
                    "blind signing is enabled, so the device must sign a LimitedUtf8 \
                     off-chain message. It refused with: {}",
                    e.detail_string()
                )
            });
            let envelope = crate::ledger::ledger_offchain_envelope(&signer.pubkey(), payload)
                .expect("envelope");
            assert!(
                signature.verify(&signer.pubkey().to_bytes(), &envelope),
                "the signature must verify against the envelope the device signed"
            );
            eprintln!("signed and verified with blind signing enabled");
            return;
        }

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "blind signing is disabled, so the device must refuse a LimitedUtf8 \
                 off-chain message -- it signed instead. Either the setting is still on, \
                 or the app stopped gating this."
            ),
        };
        // Not merely "an error": the specific one, whose whole point is that it
        // names the remedy. Upstream renders APDU 0x6808 as "Ledger operation
        // not supported", which is accurate and actionable for nobody, and a
        // regression to that wording would leave this phase green.
        assert!(
            matches!(err, crate::error::SignerError::SigningFailed(_)),
            "the refusal is a signing failure, got: {err:?}"
        );
        let detail = err.detail_string();
        assert!(
            detail.contains("blind signing"),
            "the refusal must name blind signing as the remedy, got: {detail}"
        );
        eprintln!("refused with blind signing disabled, as required: {detail}");
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
