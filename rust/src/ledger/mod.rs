//! Ledger hardware-wallet signer over USB-HID.
//!
//! Unlike the other backends in this crate (which talk to remote HTTP APIs),
//! the Ledger backend drives a physical device on the local machine through
//! [`solana-remote-wallet`](https://docs.rs/solana-remote-wallet) — Solana's
//! canonical Ledger APDU client. The private key never leaves the device, and
//! every signature must be confirmed on the device screen.
//!
//! ## Why one shared, permanent device thread
//!
//! Two independent reasons, and the second is the strict one.
//!
//! `solana-remote-wallet` is single-threaded: its `LedgerWallet` handle wraps a
//! `hidapi` device that is not [`Sync`], while the [`SolanaSigner`] trait is
//! `async` and `Send + Sync`. Confining device I/O to one OS thread bridges
//! that, and is correct on its own terms — a Ledger services one APDU exchange
//! at a time.
//!
//! But the thread must also be a **process-wide singleton that never exits**,
//! because of how IOKit schedules HID devices on macOS. See [`DEVICE_THREAD`]:
//! a per-signer thread makes any connect/drop/reconnect cycle abort the process.
//!
//! So [`LedgerSigner`] owns no thread and no device handle at all — just a
//! cached pubkey and a derivation path. Each trait method does a blocking
//! request/reply against the shared thread from inside
//! [`tokio::task::spawn_blocking`].
//!
//! ## One session per device, and what that costs
//!
//! The device thread caches **one** session per `host_device_path`. Two
//! consequences worth knowing before designing around this backend.
//!
//! One on-device confirmation at a time, per process. Signing serializes through
//! the single actor, and a dispatched APDU cannot be cancelled, so a second
//! signing request arriving while the device is mid-prompt fails fast rather
//! than queueing behind a human who may never answer.
//!
//! Two physical Ledgers can be used alternately but not concurrently. Signers
//! bound to different devices each reuse their own session, but the claim is
//! process-wide, so a command for one device fails fast while another is
//! mid-prompt. A signer opened with `None` resolves to the sole attached
//! Ledger's host path and shares the session a named signer holds on it.
//!
//! Works under any of `sdk-v2`/`sdk-v3`/`sdk-v4`. The backend needs
//! `solana-remote-wallet` 4.x — the first line carrying the Nano Gen5 product
//! IDs — whose solana-* crates do not match the ones `sdk-v2`/`sdk-v3` select.
//! That costs nothing here: pubkeys and signatures cross to the selected SDK as
//! raw bytes (see [`signature_bytes`]), so the two majors coexist in the
//! dependency graph and no type is ever required to unify.

mod dashboard;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Weak};
use std::time::Duration;

use solana_derivation_path::DerivationPath;
use solana_remote_wallet::ledger::{is_valid_ledger, LedgerWallet};
use solana_remote_wallet::remote_wallet::{is_valid_hid_device, RemoteWallet, RemoteWalletError};

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SolanaSigner, TransactionSigner};
use crate::transaction_util::TransactionUtil;

/// Default Solana derivation path: `m/44'/501'/0'`.
///
/// This matches **Ledger Live**'s Solana accounts (account index, no "change"
/// component), so the address pay derives equals the one a user sees and funds
/// in Ledger Live. (The 4-component `m/44'/501'/0'/0'` is the older Solana-CLI
/// style and derives a *different* address.)
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/501'/0'";

/// Timeout for device commands that **cannot** involve the user.
///
/// Enumeration, an unconfirmed pubkey read and the liveness probes are pure
/// host-to-device exchanges: the device either answers in milliseconds or
/// something is wrong. Seconds is generous.
pub const OPS_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for commands that wait on a human.
///
/// Signing blocks while the user reads the confirm screen, so this cannot be
/// short. Two minutes is long enough for a deliberate read-and-approve and
/// short enough that an abandoned prompt does not hold the device for the rest
/// of the process's life. Override with [`LedgerConfig::signing_timeout`].
pub const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(120);

/// How to open a [`LedgerSigner`].
///
/// Prefer this over [`LedgerSigner::connect`] when you need to control the
/// signing timeout or suppress the dashboard auto-launch. `Default` reproduces
/// `connect(None, false, None)` exactly.
#[derive(Debug, Clone)]
pub struct LedgerConfig {
    /// BIP-44 path; `None` uses [`DEFAULT_DERIVATION_PATH`].
    pub derivation_path: Option<String>,
    /// Display the derived address on the device for the user to verify. This
    /// requires a button press, so it waits on [`Self::signing_timeout`].
    pub confirm_pubkey_on_device: bool,
    /// Select one device by OS HID path when several Ledgers are attached.
    pub host_device_path: Option<String>,
    /// How long to wait on a command that needs a human. Defaults to
    /// [`DEFAULT_SIGN_TIMEOUT`].
    pub signing_timeout: Duration,
    /// Launch the Solana app from the BOLOS dashboard when a connect fails
    /// because the app is not running. Defaults to `true`.
    ///
    /// **This writes APDUs to the device without asking the host user.** Two
    /// facts about what the device does in response:
    ///
    /// - Launching the Solana app prompts for consent on the device screen.
    /// - If a *different* app is currently open, it is quit back to the
    ///   dashboard **without any on-device prompt** before that consent prompt
    ///   appears. So the first visible effect of a connect can be another app
    ///   closing, with nothing asked first.
    ///
    /// Default `true` is right for an interactive CLI, where the alternative is
    /// telling the user to go and navigate the device by hand. Set it to `false`
    /// for unattended or server-side use, where a process should not be poking a
    /// security device on its own initiative; connect then fails with the
    /// underlying "open the Solana app" error instead. A decline on the device
    /// is always surfaced as [`SignerError::UserRejected`] either way.
    pub auto_open_app: bool,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            derivation_path: None,
            confirm_pubkey_on_device: false,
            host_device_path: None,
            signing_timeout: DEFAULT_SIGN_TIMEOUT,
            auto_open_app: true,
        }
    }
}

/// Requests sent to the device-actor thread. Each carries a one-shot reply
/// channel the actor uses to return the result.
enum DeviceCommand {
    /// Establish (or reuse) a device session and read the pubkey at `path_str`.
    Connect {
        /// Released when the actor drops this command, so a caller-side
        /// timeout cannot free a device that is still busy.
        claim: DeviceClaim,
        path_str: String,
        confirm_pubkey_on_device: bool,
        binding: Arc<Binding>,
        /// Launch the Solana app from the dashboard if the connect fails.
        auto_open_app: bool,
        reply: Sender<Result<[u8; 32], SignerError>>,
    },
    /// Sign serialized transaction-message bytes (Solana app "sign" APDU).
    SignTransactionMessage {
        /// Released when the actor drops this command, so a caller-side
        /// timeout cannot free a device that is still busy.
        claim: DeviceClaim,
        path_str: String,
        message: Vec<u8>,
        /// Which device this signer was opened against, so a lost session
        /// can be re-established against the same one.
        binding: Arc<Binding>,
        /// The signer's key, which a re-established session must hold.
        pubkey: [u8; 32],
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Sign an off-chain message (Solana app "sign off-chain message" APDU).
    SignOffchainMessage {
        /// Released when the actor drops this command, so a caller-side
        /// timeout cannot free a device that is still busy.
        claim: DeviceClaim,
        path_str: String,
        message: Vec<u8>,
        /// Which device this signer was opened against, so a lost session
        /// can be re-established against the same one.
        binding: Arc<Binding>,
        /// The signer's key, which a re-established session must hold.
        pubkey: [u8; 32],
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Liveness probe: read the pubkey without on-device confirmation.
    IsAvailable {
        /// Released when the actor drops this command, so a caller-side
        /// timeout cannot free a device that is still busy.
        claim: DeviceClaim,
        path_str: String,
        binding: Arc<Binding>,
        /// The signer's key, which a re-established session must hold.
        pubkey: [u8; 32],
        reply: Sender<Result<[u8; 32], SignerError>>,
    },
    /// Is any Ledger attached, regardless of whether it is usable?
    ///
    /// Exists so callers never have to touch `hidapi` themselves; see
    /// [`device_channel`] for why that matters.
    IsAttached { reply: Sender<bool> },
    /// A [`Binding`] was dropped: close every session no live signer is bound to.
    Release,
}

/// The device a signer was opened against. Each command carries a clone, so
/// the binding outlives the signer until its last command is served.
struct Binding {
    host_device_path: Option<String>,
    /// The channel the signer connected through, which the release goes back on.
    release: Sender<DeviceCommand>,
}

impl Drop for Binding {
    fn drop(&mut self) {
        let _ = self.release.send(DeviceCommand::Release);
    }
}

impl Binding {
    /// The paths among its device's `interfaces` this binding may run on: a
    /// named binding only the one it selected, never a sibling.
    fn openable<'a>(&self, interfaces: &'a [String]) -> &'a [String] {
        match self.host_device_path {
            Some(_) => interfaces.get(..1).unwrap_or(interfaces),
            None => interfaces,
        }
    }
}

/// The one, process-wide device thread. Started on first use, never joined.
///
/// ## Why it must be a singleton
///
/// On macOS, `hidapi::HidApi::new()` enumerates through IOKit, which schedules
/// each HID device onto **the calling thread's `CFRunLoop`**
/// (`IOHIDDeviceScheduleWithRunLoop` <- `CFRunLoopAddSource`). When that thread
/// exits, its run loop goes with it, but IOKit's process-global HID manager
/// still holds the scheduled sources. The next `HidApi::new()` on a *different*
/// thread then re-applies device matching over that stale state, and the process
/// dies with SIGTRAP inside CoreFoundation's `__CFCheckCFInfoPACSignature`.
///
/// So a per-signer device thread cannot work: any create/drop/reconnect cycle
/// crashes the process. One thread that never exits keeps every HID source
/// scheduled on a run loop that stays alive, which is the only arrangement IOKit
/// tolerates. It is also the right shape anyway: a Ledger services one APDU
/// exchange at a time, so serialising through a single thread costs nothing.
static DEVICE_THREAD: std::sync::OnceLock<Sender<DeviceCommand>> = std::sync::OnceLock::new();

/// The channel every command goes out on.
///
/// In production this is always [`device_channel`]. Under `cfg(test)` a test can
/// point it at a fake actor, which is the only way to drive `sign_message` and
/// `sign_transaction` end to end without hardware -- and therefore the only way
/// to assert that those paths verify what the device hands back, rather than
/// asserting it against this file's own source text.
fn command_channel() -> Sender<DeviceCommand> {
    #[cfg(test)]
    {
        let over = tests::CHANNEL_OVERRIDE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = over.as_ref() {
            return tx.clone();
        }
    }
    device_channel().clone()
}

/// Channel to the device thread, starting it if this is the first call.
///
/// Everything that touches `hidapi` must go through here; calling
/// `HidApi::new()` from any other thread is what crashes. See [`DEVICE_THREAD`].
fn device_channel() -> &'static Sender<DeviceCommand> {
    DEVICE_THREAD.get_or_init(|| {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        // The handle is deliberately dropped: this thread outlives every signer,
        // so there is nothing to join and no handle worth keeping.
        std::thread::Builder::new()
            .name("ledger-device".to_string())
            .spawn(move || device_thread(LedgerHid, cmd_rx))
            .expect("failed to spawn the Ledger device thread");
        cmd_tx
    })
}

/// A [`SolanaSigner`] backed by a Ledger hardware wallet.
///
/// Cheap to create and drop: it holds no thread and no device handle, only the
/// cached pubkey and the derivation path to use. Dropping a signer sends
/// `Release`; the actor closes that device's session once no live signer is
/// still bound to its host path. All
/// device work happens on the shared thread described at [`DEVICE_THREAD`].
pub struct LedgerSigner {
    pubkey: Pubkey,
    path_str: String,
    /// The device this signer was opened against, carried on every later
    /// command so a lost session re-establishes against the same one rather
    /// than whichever Ledger happens to be attached.
    binding: Arc<Binding>,
    /// Timeout for the device commands that wait on a button press.
    signing_timeout: Duration,
}

impl std::fmt::Debug for LedgerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigner")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl LedgerSigner {
    /// Connect to a Ledger device and cache the public key at `derivation_path`
    /// (defaults to [`DEFAULT_DERIVATION_PATH`]).
    ///
    /// Set `confirm_pubkey_on_device` to display the derived address on the
    /// device screen for the user to verify — use this when *registering* an
    /// account, not on every signing connection.
    ///
    /// `host_device_path` selects a specific device by its OS HID path when more
    /// than one Ledger is connected. Pass `None` to use the sole connected
    /// device; if several are attached and `None` is given, this returns
    /// [`SignerError::NotAvailable`] with the device count. Host paths are not
    /// placed in the error; `just rust-ledger-diagnose` lists them.
    ///
    /// Naming a path does **not** make two devices usable concurrently. The
    /// device thread caches one session per path, so signers bound to different
    /// devices alternate without re-establishing, but one process-wide claim
    /// still serializes them. See the module documentation.
    ///
    /// Requires the Ledger to be plugged in, unlocked, and running the Solana
    /// app. On Linux, the appropriate `udev` rules must be installed.
    ///
    /// **Blocking:** this blocks the calling thread until the device responds —
    /// with `confirm_pubkey_on_device` set, until the user presses a button. Do
    /// not call it directly from an async task; use the async
    /// [`Signer::from_ledger`](crate::Signer::from_ledger) factory (which runs it
    /// on the blocking pool) or wrap it in [`tokio::task::spawn_blocking`].
    pub fn connect(
        derivation_path: Option<&str>,
        confirm_pubkey_on_device: bool,
        host_device_path: Option<&str>,
    ) -> Result<Self, SignerError> {
        Self::connect_with(LedgerConfig {
            derivation_path: derivation_path.map(str::to_string),
            confirm_pubkey_on_device,
            host_device_path: host_device_path.map(str::to_string),
            ..LedgerConfig::default()
        })
    }

    /// Connect using an explicit [`LedgerConfig`].
    ///
    /// Use this to set the signing timeout or to turn off the dashboard
    /// auto-launch; see [`LedgerConfig`] for what each option costs.
    ///
    /// **Blocking**, exactly as [`LedgerSigner::connect`] is. Every command this
    /// signer later issues is bounded: [`OPS_TIMEOUT`] for exchanges
    /// that cannot involve the user, and [`LedgerConfig::signing_timeout`] for
    /// the ones that wait on a button press.
    pub fn connect_with(config: LedgerConfig) -> Result<Self, SignerError> {
        let LedgerConfig {
            derivation_path,
            confirm_pubkey_on_device,
            host_device_path,
            signing_timeout,
            auto_open_app,
        } = config;

        let path_str = derivation_path.unwrap_or_else(|| DEFAULT_DERIVATION_PATH.to_string());
        // Validate before troubling the device, so a typo is a clear config
        // error rather than an obscure APDU failure.
        DerivationPath::from_absolute_path_str(&path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

        // A connect can reach the user in two ways: an explicit on-device
        // address confirmation, and the dashboard auto-launch, which most
        // firmware asks the user to approve. Either one means this has to wait
        // on a human rather than on the wire.
        let timeout = if confirm_pubkey_on_device || auto_open_app {
            signing_timeout
        } else {
            OPS_TIMEOUT
        };

        // A connect can reach the user too, so it takes the same claim rather
        // than racing a signature already at the confirm screen.
        let claim = DeviceClaim::acquire()?;
        let channel = command_channel();
        let binding = Arc::new(Binding {
            host_device_path,
            release: channel.clone(),
        });
        let pubkey_bytes = request_on(&channel, timeout, claim, |claim, reply| {
            DeviceCommand::Connect {
                claim,
                path_str: path_str.clone(),
                confirm_pubkey_on_device,
                binding: Arc::clone(&binding),
                auto_open_app,
                reply,
            }
        })?;

        Ok(Self {
            pubkey: Pubkey::from(pubkey_bytes),
            path_str,
            binding,
            signing_timeout,
        })
    }

    /// The device this signer was opened against, if one was named.
    pub fn host_device_path(&self) -> Option<&str> {
        self.binding.host_device_path.as_deref()
    }

    /// The timeout this signer applies to commands that wait on a button press.
    pub fn signing_timeout(&self) -> Duration {
        self.signing_timeout
    }

    /// Is a Ledger attached, whether or not it is usable right now?
    ///
    /// Answers without requiring the device to be unlocked or the Solana app to
    /// be open, so a caller can tell "no hardware" apart from "hardware present
    /// but not ready" — which are very different things to report to a user.
    /// Goes through the device thread; see [`DEVICE_THREAD`].
    pub fn is_attached() -> bool {
        if device_is_busy() {
            // Mid-command, so this probe cannot be served promptly. Reporting
            // "no device" would be a lie, but so would blocking: this exists to
            // be quick. Callers that need the distinction should ask
            // `LedgerSigner::connect`, which returns a real error.
            return false;
        }
        let cmd_tx = device_channel();
        let (reply_tx, reply_rx) = mpsc::channel();
        if cmd_tx
            .send(DeviceCommand::IsAttached { reply: reply_tx })
            .is_err()
        {
            return false;
        }
        match reply_rx.recv_timeout(OPS_TIMEOUT) {
            Ok(attached) => attached,
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for LedgerSigner {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    /// Sign `message` as a Solana **off-chain message**.
    ///
    /// A hardware wallet cannot raw-ed25519-sign arbitrary bytes the way the
    /// software backends do. It signs a *structured* off-chain message: the
    /// payload is wrapped in an envelope and the device signs the envelope. The
    /// returned signature therefore covers the **envelope**, not the raw
    /// `message` bytes — a plain `signature.verify(pubkey, message)` over the
    /// payload will fail. Rebuild the same bytes with
    /// [`ledger_offchain_envelope`] to verify. This deviates from the raw-bytes
    /// contract of the software backends by necessity; see the `sign_message`
    /// note on [`SolanaSigner`].
    ///
    /// Note the envelope is **not** what `solana_offchain_message` produces —
    /// see [`ledger_offchain_envelope`] for why, and for the layout.
    ///
    /// **Blind signing.** A payload that is not printable ASCII is sent as
    /// format 1 (LimitedUtf8), and the Solana app refuses those unless the user
    /// has enabled blind signing in its settings. Keep payloads to printable
    /// ASCII to avoid the requirement entirely.
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let serialized = ledger_offchain_envelope(&self.pubkey, message)?;
        // Kept for the post-signing verification below; `serialized` itself moves
        // into the device closure.
        let verify_against = serialized.clone();
        let path_str = self.path_str.clone();
        let binding = Arc::clone(&self.binding);
        let pubkey = self.pubkey.to_bytes();
        let timeout = self.signing_timeout;
        // One process serializes to one on-device confirmation at a time. Claim
        // the device before enqueueing, so a racing caller fails fast instead of
        // waiting out its whole timeout behind someone else's prompt. Held until
        // this function returns, by any path.
        let claim = DeviceClaim::acquire()?;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&command_channel(), timeout, claim, |claim, reply| {
                DeviceCommand::SignOffchainMessage {
                    claim,
                    path_str,
                    message: serialized,
                    binding,
                    pubkey,
                    reply,
                }
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;
        let signature = Signature::from(sig_bytes);
        // Same signature-binding invariant the remote backends hold to: never
        // hand back a signature that does not verify against this signer's key
        // over the bytes we computed. Here that also pins the envelope: the
        // device signed the envelope, so verification is against it and not the
        // raw payload.
        crate::signature_util::verify_or_reject(&signature, &self.pubkey, &verify_against)?;
        Ok(signature)
    }

    /// Liveness probe. Never waits on the user, so it is bounded by
    /// [`OPS_TIMEOUT`] rather than the signing timeout, and reports
    /// `false` rather than blocking when the device thread is wedged, and
    /// `false` when the device answers with another key.
    async fn is_available(&self) -> bool {
        let pubkey = self.pubkey;
        let path_str = self.path_str.clone();
        let binding = Arc::clone(&self.binding);
        tokio::task::spawn_blocking(move || {
            // Probe, not an operation: if someone else holds the device, report
            // "not available" rather than queueing behind their prompt.
            let Some(claim) = DeviceClaim::try_acquire() else {
                return false;
            };
            let (reply_tx, reply_rx) = mpsc::channel();
            if command_channel()
                .send(DeviceCommand::IsAvailable {
                    claim,
                    path_str,
                    binding,
                    pubkey: pubkey.to_bytes(),
                    reply: reply_tx,
                })
                .is_err()
            {
                return false;
            }
            match reply_rx.recv_timeout(OPS_TIMEOUT) {
                Ok(read) => read.is_ok_and(|bytes| Pubkey::from(bytes) == pubkey),
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl TransactionSigner for LedgerSigner {
    /// Sign `tx` on the device, in place.
    ///
    /// The serialized transaction *message* goes to the Solana app's
    /// transaction-parsing APDU, which is the only way a Ledger will sign a
    /// transaction — it cannot raw-ed25519-sign arbitrary bytes. Legacy, v0 and
    /// v1 all work, because what crosses to the device is
    /// `VersionedMessage::serialize()` either way; the device renders what it
    /// can parse and falls back to blind signing otherwise (which the user must
    /// have enabled in the app's settings).
    ///
    /// The signature covers exactly the bytes the caller supplied, so it
    /// verifies identically to a software backend's and needs no special
    /// handling server-side.
    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let message = tx.message.serialize();
        // Kept for the post-signing verification below; `message` itself moves
        // into the device closure.
        let verify_against = message.clone();
        let path_str = self.path_str.clone();
        let binding = Arc::clone(&self.binding);
        let pubkey = self.pubkey.to_bytes();
        let timeout = self.signing_timeout;
        // One process serializes to one on-device confirmation at a time. Claim
        // the device before enqueueing, so a racing caller fails fast instead of
        // waiting out its whole timeout behind someone else's prompt. Held until
        // this function returns, by any path.
        let claim = DeviceClaim::acquire()?;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&command_channel(), timeout, claim, |claim, reply| {
                DeviceCommand::SignTransactionMessage {
                    claim,
                    path_str,
                    message,
                    binding,
                    pubkey,
                    reply,
                }
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;

        let signature = Signature::from(sig_bytes);
        // Signature binding, as the remote backends do it: reject rather than
        // attach if the device's signature does not verify against this signer's
        // key over the exact bytes we sent. On a hardware path this is what
        // catches a transport-level corruption, or a device answering for a
        // different derivation path than the one we cached a pubkey for.
        crate::signature_util::verify_or_reject(&signature, &self.pubkey, &verify_against)?;
        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey(), signature)?;
        let signed_transaction = (TransactionUtil::serialize_transaction(tx)?, signature);
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }
}

/// Longest payload that fits an off-chain message envelope bound for a Ledger.
///
/// Two independent caps apply and the tighter one wins. The device rejects a
/// total envelope over `MAX_OFFCHAIN_MESSAGE_LENGTH` (Solana's 1232-byte packet
/// size). Before that, `solana-remote-wallet` refuses to send anything over
/// `v0::OffchainMessage::MAX_LEN_LEDGER + v0::OffchainMessage::HEADER_LEN`
/// = 1212 + 3 = 1215, a guard it computes from the *crate's* header size (3) and
/// not the header the device actually parses (85). Its guard is therefore the
/// binding one, and 1215 - 85 is what is left for the payload.
pub const MAX_OFFCHAIN_PAYLOAD_LEN: usize = 1215 - OFFCHAIN_HEADER_LEN_ONE_SIGNER;

/// Envelope header length for a single signer:
/// 16 (signing domain) + 1 (version) + 32 (application domain) + 1 (format)
/// + 1 (signer count) + 32 (one signer) + 2 (message length).
const OFFCHAIN_HEADER_LEN_ONE_SIGNER: usize = 16 + 1 + 32 + 1 + 1 + 32 + 2;

/// Build the off-chain message envelope the **Ledger Solana app** expects.
///
/// Cannot use `solana_offchain_message`: different layout, output rejected as
/// `SolanaInvalidMessageHeader` (verified on Nano Gen5).
///
/// What the crate emits (20-byte header):
///   signing domain (16) ‖ version (1) ‖ format (1) ‖ length (2) ‖ message
///
/// What the app parses for v0 (85-byte header for one signer):
///   signing domain (16) ‖ version=0 (1) ‖ **application domain (32)**
///   ‖ format (1) ‖ **signer count (1)** ‖ **signers (32 each)**
///   ‖ length (2, little-endian) ‖ message
///
/// The crate omits the application domain, the signer count and the signer list
/// — 65 bytes for a single signer. The signer list is the part that matters
/// most: the app derives the pubkey at the requested path and rejects the
/// message unless that pubkey appears in the list, so the envelope has to name
/// the signer. (Source: `LedgerHQ/app-solana`, `libsol/parser.c`
/// `parse_offchain_message_header` and `src/handle_sign_offchain_message.c`.)
///
/// The application domain is left all-zero, which the app supports explicitly
/// and displays as "Domain not provided". A future integration that wants the
/// device to show a bound application identity should populate it — the value is
/// covered by the signature, so it cannot be altered in flight.
///
/// The format byte is derived from the payload rather than fixed: 0
/// (RestrictedAscii) when the payload is printable ASCII, 1 (LimitedUtf8)
/// otherwise. Format 2 (ExtendedUtf8) is deliberately unsupported by hardware
/// wallets per the spec, and the app rejects it, so a payload that is not valid
/// UTF-8 is refused here rather than at the device.
pub fn ledger_offchain_envelope(signer: &Pubkey, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
    // The app rejects a zero-length message (`header.length == 0`).
    if payload.is_empty() {
        return Err(SignerError::ConfigError(
            "off-chain message payload is empty; a Ledger will not sign it".to_string(),
        ));
    }
    if payload.len() > MAX_OFFCHAIN_PAYLOAD_LEN {
        return Err(SignerError::ConfigError(format!(
            "off-chain message payload is {} bytes; a Ledger accepts at most {}",
            payload.len(),
            MAX_OFFCHAIN_PAYLOAD_LEN
        )));
    }
    // Mirror the app's own content checks so the failure is local and legible
    // rather than an opaque APDU rejection after a round-trip.
    let format: u8 = if payload.iter().all(|b| (0x20..=0x7e).contains(b)) {
        0 // RestrictedAscii
    } else if std::str::from_utf8(payload).is_ok() {
        1 // LimitedUtf8
    } else {
        return Err(SignerError::ConfigError(
            "off-chain message payload is not valid UTF-8; a Ledger will not sign it".to_string(),
        ));
    };

    let mut out = Vec::with_capacity(OFFCHAIN_HEADER_LEN_ONE_SIGNER + payload.len());
    // Taken from the crate rather than hardcoded, so the domain stays in step
    // with upstream even though the rest of the layout cannot.
    out.extend_from_slice(solana_offchain_message::OffchainMessage::SIGNING_DOMAIN);
    out.push(0); // header version 0
    out.extend_from_slice(&[0u8; 32]); // application domain: not provided
    out.push(format);
    out.push(1); // exactly one signer
    out.extend_from_slice(&signer.to_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    debug_assert_eq!(out.len(), OFFCHAIN_HEADER_LEN_ONE_SIGNER + payload.len());
    Ok(out)
}

/// Set while the device thread is inside a command that touches the device.
///
/// A dispatched APDU cannot be cancelled: `solana-remote-wallet`'s
/// `Ledger::read` (ledger.rs:241 in 4.2.2) sits in `hidapi`'s untimed blocking
/// `HidDevice::read`, and nothing on the host can interrupt it. So a caller-side
/// deadline is the only available remedy, and on its own it is not enough: the
/// actor is a single serialized thread, so handing one caller its thread back
/// still leaves everyone else queued behind a human who may never press the
/// button, each burning a full timeout in turn.
///
/// This flag is what makes the second signer fail in milliseconds instead. It is
/// set by the actor around device-touching work, so it reports what the device
/// is actually doing rather than what a caller inferred.
static DEVICE_BUSY: AtomicBool = AtomicBool::new(false);

/// True while some caller holds the device.
///
/// Only meaningful for the cheap probes, which report "not available" rather
/// than queueing. Anything that touches the device takes a [`DeviceClaim`].
///
fn device_is_busy() -> bool {
    DEVICE_BUSY.load(Ordering::SeqCst)
}

/// The error a caller gets instead of queueing behind an on-device prompt.
///
/// Deliberately worded to be distinguishable from the generic "no Ledger"
/// message: the device is present and healthy, it is simply mid-conversation
/// with someone. Reusing `NotAvailable` rather than adding a variant keeps the
/// cross-language error contract intact; the message carries the distinction.
fn busy_error() -> SignerError {
    SignerError::NotAvailable(BUSY_DETAIL.to_string())
}

/// The exact detail [`busy_error`] carries.
///
/// A constant because it is load-bearing: `SignerError` has one `NotAvailable`
/// variant for every availability cause (adding variants would break the
/// cross-language error contract), so this message *is* the discriminator that
/// separates "the device is held" from "there is no device". Both the unit
/// tests and the hardware suite classify on it, and the hardware suite's
/// decision to skip or fail turns on getting that right, so neither may drift
/// from the message by editing a string literal.
pub(crate) const BUSY_DETAIL: &str =
    "Ledger is busy with another operation or awaiting on-device confirmation";

/// The detail carried when `hidapi` saw no Ledger-vendor device at all.
///
/// The one failure that proves there is no hardware, as opposed to hardware
/// that cannot be used: every other availability cause -- held, locked, wrong
/// app, attached but not enumerated -- is raised with a device present. A
/// constant for the same reason as [`BUSY_DETAIL`]: the hardware suite's
/// decision to skip rather than fail rests on it, and `SignerError` has no
/// variant to carry the distinction.
pub(crate) const NO_DEVICE_DETAIL: &str =
    "no Ledger device found (plug in, unlock, and open the Solana app)";

/// The detail carried when a Ledger opened but did not answer. A constant so a
/// failed open can rank it above the others.
const LOCKED_DETAIL: &str =
    "Ledger did not answer. It is either locked — unlock it and open the Solana app — \
     or another application is holding the device, so quit Ledger Live and any other \
     wallet software. Then retry.";

/// An exclusive claim on the device, released when dropped.
///
/// **The claim is moved into the command and dropped by the actor**, not held by
/// the caller. That matters: a caller-held guard is released when the caller
/// returns, including when it returns from a *timeout*, while the actor can
/// still be blocked indefinitely in the untimed HID read. Releasing then would
/// let the next caller acquire and queue behind an operation that is still
/// running, waiting out its own full timeout instead of failing fast, which is
/// the exact stall the claim exists to prevent. So ownership crosses the channel
/// and the release happens when the device work actually finishes.
///
/// The claim is taken **before** the command is enqueued, with a single
/// `compare_exchange`, so exactly one of any number of racing callers wins and
/// the rest get [`busy_error`] immediately.
///
/// Release is `Drop`, so it survives every exit path: a normal reply, a timeout,
/// an error, or a panic unwinding out of the caller's task. Enforcing this in
/// the actor instead was the alternative and it does not work: the actor cannot
/// refuse a command it has not dequeued yet, so a queued second signature would
/// still sit behind the first, which is the bug.
///
/// The claim is process-wide, not per device: one thread serves every Ledger,
/// so a command for device B would queue behind device A's untimed HID read.
struct DeviceClaim;

impl DeviceClaim {
    /// Take the claim, or report the device busy.
    fn acquire() -> Result<Self, SignerError> {
        DEVICE_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Self)
            .map_err(|_| busy_error())
    }

    /// Take the claim, or give up. For probes, which report unavailability
    /// rather than failing.
    fn try_acquire() -> Option<Self> {
        DEVICE_BUSY
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for DeviceClaim {
    fn drop(&mut self) {
        DEVICE_BUSY.store(false, Ordering::SeqCst);
    }
}

/// Send a command to the device actor and block for its reply, up to `timeout`.
///
/// Called from inside `spawn_blocking`. On timeout the reply receiver is
/// dropped; the actor still finishes the command and keeps its session.
fn request_on<T: Send + 'static>(
    cmd_tx: &Sender<DeviceCommand>,
    timeout: Duration,
    claim: DeviceClaim,
    build: impl FnOnce(DeviceClaim, Sender<Result<T, SignerError>>) -> DeviceCommand,
) -> Result<T, SignerError> {
    let (reply_tx, reply_rx) = mpsc::channel();
    // On a send failure the command comes back inside `SendError` and drops
    // here, which releases the claim: the actor is gone and will not do it.
    cmd_tx.send(build(claim, reply_tx)).map_err(|_| {
        SignerError::NotAvailable("Ledger device thread is not running".to_string())
    })?;
    match reply_rx.recv_timeout(timeout) {
        Ok(result) => result,
        // The actor keeps running and will answer into a receiver nobody is
        // holding, which its `let _ = reply.send(..)` already tolerates.
        Err(RecvTimeoutError::Timeout) => Err(busy_error()),
        Err(RecvTimeoutError::Disconnected) => Err(SignerError::NotAvailable(
            "Ledger device thread stopped".to_string(),
        )),
    }
}

/// The device calls [`device_thread`] makes, so its session handling can be
/// driven without hardware.
trait Hardware {
    type Wallet;
    /// The attached Ledgers, as one enumeration listed them.
    type Listing;
    /// List attached Ledgers without opening any.
    fn list(&self) -> Result<Self::Listing, SignerError>;
    /// The host paths in `listing` of the interfaces of the device at
    /// `host_device_path`, its own first, or of the only one when it is `None`.
    fn resolve(
        &self,
        listing: &Self::Listing,
        host_device_path: Option<&str>,
    ) -> Result<Vec<String>, SignerError>;
    /// Open the device in `listing` at `host_path` and nothing else, with the
    /// listed path it opened. `None` when no Ledger is listed there, as when a
    /// held session's device was unplugged.
    fn open(
        &self,
        listing: &Self::Listing,
        host_path: &str,
    ) -> Result<Option<(String, Self::Wallet)>, SignerError>;
    /// See [`no_ledger_enumerated_error`].
    fn unenumerated(&self) -> SignerError;
    /// See [`dashboard::ensure_solana_app_open`].
    fn launch_app(&self, host_device_path: Option<&str>) -> Result<bool, SignerError>;
    fn pubkey(
        &self,
        wallet: &Self::Wallet,
        path: &DerivationPath,
        confirm: bool,
    ) -> Result<[u8; 32], SignerError>;
    fn sign_transaction(
        &self,
        wallet: &Self::Wallet,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64], SignerError>;
    fn sign_offchain(
        &self,
        wallet: &Self::Wallet,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64], SignerError>;
    fn is_attached(&self) -> bool;
    /// Wait out part of the USB re-enumeration an app launch triggers.
    fn settle(&self);
}

/// [`Hardware`] over `hidapi` and `solana-remote-wallet`, on [`DEVICE_THREAD`].
struct LedgerHid;

/// The Ledgers one `hidapi` enumeration listed, and the context to open them in.
struct HidListing {
    api: hidapi::HidApi,
    ledgers: Vec<hidapi::DeviceInfo>,
    paths: Vec<String>,
}

impl Hardware for LedgerHid {
    type Wallet = LedgerWallet;
    type Listing = HidListing;

    fn list(&self) -> Result<HidListing, SignerError> {
        let api = hid_api()?;
        let ledgers: Vec<hidapi::DeviceInfo> = listed_ledgers(&api)?.into_iter().cloned().collect();
        let paths = ledgers
            .iter()
            .map(|d| d.path().to_string_lossy().into_owned())
            .collect();
        Ok(HidListing {
            api,
            ledgers,
            paths,
        })
    }

    fn resolve(
        &self,
        listing: &HidListing,
        host_device_path: Option<&str>,
    ) -> Result<Vec<String>, SignerError> {
        let candidates: Vec<dashboard::Candidate<'_>> = listing
            .ledgers
            .iter()
            .zip(&listing.paths)
            .map(|(d, path)| dashboard::Candidate {
                path,
                serial: d.serial_number(),
            })
            .collect();
        match host_device_path {
            Some(want) => device_interfaces(&candidates, want),
            None => sole_interfaces(&candidates),
        }
    }

    fn open(
        &self,
        listing: &HidListing,
        host_path: &str,
    ) -> Result<Option<(String, LedgerWallet)>, SignerError> {
        let listed: Vec<&str> = listing.paths.iter().map(String::as_str).collect();
        let Some(i) = dashboard::select_ledger(&listed, host_path) else {
            return Ok(None);
        };
        let info = &listing.ledgers[i];
        let device = info.open_device(&listing.api).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("cannot open Ledger at `{host_path}`: {_e}");
            unopenable_error()
        })?;
        let mut wallet = LedgerWallet::new(device);
        wallet.pretty_path = wallet
            .read_device(info)
            .map_err(map_rw_err)?
            .get_pretty_path();
        Ok(Some((listed[i].to_string(), wallet)))
    }

    fn unenumerated(&self) -> SignerError {
        no_ledger_enumerated_error()
    }

    fn launch_app(&self, host_device_path: Option<&str>) -> Result<bool, SignerError> {
        dashboard::ensure_solana_app_open(host_device_path)
    }

    fn pubkey(
        &self,
        wallet: &LedgerWallet,
        path: &DerivationPath,
        confirm: bool,
    ) -> Result<[u8; 32], SignerError> {
        wallet
            .get_pubkey(path, confirm)
            .map(|pubkey| pubkey.to_bytes())
            .map_err(map_rw_err)
    }

    fn sign_transaction(
        &self,
        wallet: &LedgerWallet,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64], SignerError> {
        wallet
            .sign_message(path, message)
            .map_err(map_rw_err)
            .and_then(signature_bytes)
    }

    fn sign_offchain(
        &self,
        wallet: &LedgerWallet,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<[u8; 64], SignerError> {
        wallet
            .sign_offchain_message(path, message)
            .map_err(map_rw_err)
            .and_then(signature_bytes)
    }

    fn is_attached(&self) -> bool {
        hidapi::HidApi::new()
            .map(|api| api.device_list().any(|d| d.vendor_id() == LEDGER_VID))
            .unwrap_or(false)
    }

    fn settle(&self) {
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The host paths of the one physical Ledger's interfaces among `candidates`,
/// counting sibling interfaces of one device once.
fn sole_interfaces(candidates: &[dashboard::Candidate<'_>]) -> Result<Vec<String>, SignerError> {
    // `sole_ledger` succeeds only when every candidate is one device's interface.
    dashboard::sole_ledger(candidates)?;
    Ok(candidates.iter().map(|c| c.path.to_string()).collect())
}

/// The host paths of the interfaces of the device `want` selects among
/// `candidates`, the selected one first.
fn device_interfaces(
    candidates: &[dashboard::Candidate<'_>],
    want: &str,
) -> Result<Vec<String>, SignerError> {
    let listed: Vec<&str> = candidates.iter().map(|c| c.path).collect();
    let selected = dashboard::select_ledger(&listed, want).ok_or_else(|| no_device_at(want))?;
    let siblings = candidates
        .iter()
        .enumerate()
        .filter(|(i, c)| *i != selected && dashboard::same_device(c, &candidates[selected]));
    Ok(std::iter::once(listed[selected])
        .chain(siblings.map(|(_, c)| c.path))
        .map(str::to_string)
        .collect())
}

fn hid_api() -> Result<hidapi::HidApi, SignerError> {
    // A failure to bring up the HID subsystem is an *availability* problem,
    // not a signing failure — map it to NotAvailable directly rather than
    // letting map_rw_err's catch-all bucket it as SigningFailed (which would
    // also make the no-device unit test panic on CI runners lacking libhidapi).
    hidapi::HidApi::new().map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Ledger HID subsystem unavailable: {_e}");
        SignerError::NotAvailable(
            "the Ledger HID subsystem is unavailable. On Linux this is usually \
         missing udev rules; otherwise no HID backend could be initialised."
                .to_string(),
        )
    })
}

/// Attached Ledgers, under the filter `solana-remote-wallet`'s own enumeration
/// applies. Listing opens nothing.
fn listed_ledgers(api: &hidapi::HidApi) -> Result<Vec<&hidapi::DeviceInfo>, SignerError> {
    let ledgers: Vec<&hidapi::DeviceInfo> = api
        .device_list()
        .filter(|d| {
            is_valid_hid_device(d.usage_page(), d.interface_number())
                && is_valid_ledger(d.vendor_id(), d.product_id())
        })
        .collect();
    if ledgers.is_empty() {
        return Err(no_ledger_enumerated_error());
    }
    Ok(ledgers)
}

fn no_device_at(host_path: &str) -> SignerError {
    SignerError::NotAvailable(format!("no Ledger device at host path `{host_path}`"))
}

fn unopenable_error() -> SignerError {
    SignerError::NotAvailable(format!(
        "a Ledger device was found but could not be opened. Another application may be \
         holding it, so quit Ledger Live and any other wallet software, then retry.\
         {LINUX_UDEV_HINT}"
    ))
}

fn another_device_error() -> SignerError {
    SignerError::NotAvailable(
        "the Ledger found is not the one this signer was connected to".to_string(),
    )
}

/// Host paths identify devices to a caller but are host-local detail, so they
/// go to the `unsafe-debug` log and the error carries only the count.
fn multiple_devices_error(count: usize) -> SignerError {
    SignerError::NotAvailable(format!(
        "{count} Ledger devices connected; pass host_device_path to select one. Run \
         `just rust-ledger-diagnose` to list them."
    ))
}

/// Ledger USB vendor id. Single definition to prevent copy rot.
const LEDGER_VID: u16 = 0x2c97;

/// Product ids the Nano Gen5 presents, added to `solana-remote-wallet` in 4.1.
///
/// Duplicated from upstream deliberately, and only to *diagnose*: it lets a
/// build whose resolved `solana-remote-wallet` predates 4.1 say why the device
/// in the user's hand is invisible, rather than reporting "no Ledger found"
/// while one is plugged in. Nothing is selected or driven from this list, so it
/// drifting behind upstream costs a less specific message and nothing more.
/// (Source: `solana-remote-wallet` `ledger.rs`, `LEDGER_NANO_GEN5_PIDS`.)
const GEN5_PIDS: [u16; 33] = [
    0x0008, 0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8006, 0x8007, 0x8008, 0x8009, 0x800a,
    0x800b, 0x800c, 0x800d, 0x800e, 0x800f, 0x8010, 0x8011, 0x8012, 0x8013, 0x8014, 0x8015, 0x8016,
    0x8017, 0x8018, 0x8019, 0x801a, 0x801b, 0x801c, 0x801d, 0x801e, 0x801f,
];

/// Product ids of Ledger-vendor devices physically attached, as `hidapi` sees
/// them. Deduplicated, because a Ledger exposes several HID interfaces.
fn attached_ledger_pids() -> Vec<u16> {
    let Ok(api) = hidapi::HidApi::new() else {
        return Vec::new();
    };
    let mut pids: Vec<u16> = api
        .device_list()
        .filter(|d| d.vendor_id() == LEDGER_VID)
        .map(|d| d.product_id())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// The error for "no Ledger enumerated", enriched when one is in fact attached.
///
/// This is the silent-fork guard. `solana-remote-wallet` selects devices by a
/// per-model product-id allowlist, so a model it predates is not rejected with
/// an explanation -- it simply never appears, and every layer above reports "no
/// Ledger device found" while the user is holding one that is plugged in,
/// unlocked and running the app. That is the single most misleading failure this
/// backend can produce, and it is entirely a function of which
/// `solana-remote-wallet` the consumer's dependency graph resolved.
///
/// So: ask `hidapi` directly. If a Ledger-vendor device is attached that
/// `solana-remote-wallet` did not enumerate, say so and name the version
/// requirement instead of blaming the cable.
fn no_ledger_enumerated_error() -> SignerError {
    let attached = attached_ledger_pids();
    if attached.is_empty() {
        return SignerError::NotAvailable(NO_DEVICE_DETAIL.to_string());
    }
    SignerError::NotAvailable(unenumerated_detail(&attached, RESOLVED_REMOTE_WALLET))
}

/// Which `solana-remote-wallet` this build actually resolved, or `unknown`.
///
/// Set by `build.rs` from the lockfile governing the build. `unknown` is a real
/// answer, not a failure: a consumer pulling this crate from crates.io has its
/// lockfile somewhere we cannot see, and the message below has to be honest
/// about that rather than assert a version.
const RESOLVED_REMOTE_WALLET: &str = env!("SOLANA_REMOTE_WALLET_VERSION");

/// Whether the resolved `solana-remote-wallet` carries the Nano Gen5 product
/// ids, as far as we can actually tell.
///
/// Three states, because two would force a guess. The Gen5 ids arrived in 4.1,
/// so 4.0.x demonstrably cannot see the device and 4.1+ demonstrably can -- but
/// [`RESOLVED_REMOTE_WALLET`] is `unknown` whenever the lockfile was out of
/// reach, and an unknown version is evidence of neither. Collapsing it into
/// either definite answer is how a diagnostic starts asserting things it never
/// read, in whichever direction the collapse happens to fall.
#[derive(Debug, PartialEq, Eq)]
enum Gen5Support {
    /// Read a version, and it predates 4.1.
    Absent,
    /// Read a version, and it is 4.1 or later.
    Present,
    /// No version to read, or one that does not parse.
    Unknown,
}

/// Classify [`RESOLVED_REMOTE_WALLET`]-shaped strings. See [`Gen5Support`].
fn gen5_support(resolved: &str) -> Gen5Support {
    let mut parts = resolved.split('.');
    let (Some(major), Some(minor)) = (parts.next(), parts.next()) else {
        return Gen5Support::Unknown;
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) else {
        return Gen5Support::Unknown;
    };
    match (major, minor) {
        // Below the 4.x line entirely: the backend does not build against it,
        // but classify honestly rather than pretending it is 4.1+.
        (0..=3, _) => Gen5Support::Absent,
        (4, 0) => Gen5Support::Absent,
        _ => Gen5Support::Present,
    }
}

/// The message for "a Ledger is attached and this build did not enumerate it".
/// Reports the version rather than inferring the cause, only making the 4.0.x
/// diagnosis when it is actually resolved. Otherwise both causes are offered
/// without ranking: they differ in whether a raw HID open succeeds.
fn unenumerated_detail(attached: &[u16], resolved: &str) -> String {
    let pid_list = attached
        .iter()
        .map(|p| format!("0x{p:04x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let gen5 = attached.iter().any(|p| GEN5_PIDS.contains(p));

    // The two remaining causes, shared by the branches that cannot rule the
    // version in or out.
    const OTHER_CAUSES: &str = "the Solana app's configuration format -- app 1.16.0 answers \
         GET_APP_CONFIGURATION with seven bytes where solana-remote-wallet requires exactly \
         five, which is https://github.com/anza-xyz/agave/pull/15100 and needs that fix or \
         an older app; or another application holding the device, in which case quit Ledger \
         Live and any other wallet software";

    let cause = match (gen5, gen5_support(resolved)) {
        // The version is the answer, and it has been read rather than assumed.
        (true, Gen5Support::Absent) => format!(
            "This is a Nano Gen5, and this build resolved solana-remote-wallet {resolved}, \
             which predates the Gen5 product ids added in 4.1 and therefore cannot see the \
             device at all. 4.0.x is what the Solana 3.x crate line selects."
        ),
        // Ruling the version out is also a claim, and this is the only branch
        // entitled to make it: a version was read and it is 4.1 or later.
        (true, Gen5Support::Present) => format!(
            "This is a Nano Gen5, and this build resolved solana-remote-wallet {resolved}, \
             which does carry the Gen5 product ids, so the crate version is not the cause. \
             Two causes remain and this layer cannot tell them apart: {OTHER_CAUSES}."
        ),
        // Nothing was read, so nothing is ruled in or out. Saying "the version
        // is not the cause" here would send a consumer who really did resolve
        // 4.0.x chasing the wrong two causes -- the same mistake as blaming a
        // version unread, pointing the other way.
        (true, Gen5Support::Unknown) => format!(
            "This is a Nano Gen5, and this build's solana-remote-wallet version could not \
             be determined ({resolved}), so the version cannot be ruled out. Check it with \
             `just rust-which-remote-wallet`, or `cargo tree -i solana-remote-wallet` \
             outside this repository. If it is 4.0.x it cannot see this device at all and \
             that is the whole problem. If it is 4.1 or later, two causes remain: \
             {OTHER_CAUSES}."
        ),
        (false, Gen5Support::Unknown) => format!(
            "This build's solana-remote-wallet version could not be determined \
             ({resolved}), and whichever one it is did not recognise that product id, so it \
             never enumerated the device. A newer solana-remote-wallet may be required; \
             check which one you have with `just rust-which-remote-wallet`."
        ),
        (false, _) => format!(
            "This build resolved solana-remote-wallet {resolved}, which does not recognise \
             that product id, so it never enumerated the device. A newer \
             solana-remote-wallet may be required."
        ),
    };

    format!(
        "a Ledger device is attached (product id {pid_list}) but this build did not \
         enumerate it. {cause} Run `just rust-ledger-diagnose` to separate them: an \
         app-configuration mismatch leaves the BOLOS dashboard answering normally and only \
         enumeration failing, while a process holding the device fails even a raw HID \
         open.{LINUX_UDEV_HINT}"
    )
}

/// The device thread body. Runs for the life of the process.
///
/// Holds at most one open session per device and reuses it across commands.
/// A named `LedgerSigner::connect` reuses its device's session; an unnamed one
/// lists devices on every connect. A device error drops only that device's
/// session, so its next command re-establishes rather than reusing a handle to
/// a device that has been unplugged, locked or switched apps. A session closes
/// once no live signer is bound to it.
fn device_thread<H: Hardware>(hardware: H, cmd_rx: Receiver<DeviceCommand>) {
    let mut sessions = Sessions {
        hardware,
        open: HashMap::new(),
        bound: HashMap::new(),
    };

    // Every command needs the caller's derivation path parsed; `connect` has
    // already validated it, so a failure here is genuinely unexpected.
    fn parse(path_str: &str) -> Result<DerivationPath, SignerError> {
        DerivationPath::from_absolute_path_str(path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))
    }

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            DeviceCommand::Connect {
                claim: _claim,
                path_str,
                confirm_pubkey_on_device,
                binding,
                auto_open_app,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    sessions.connect(&binding, &path, confirm_pubkey_on_device, auto_open_app)
                });
                let _ = reply.send(result);
            }

            DeviceCommand::SignTransactionMessage {
                claim: _claim,
                path_str,
                message,
                binding,
                pubkey,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    sessions.run(&binding, &path, &pubkey, |hardware, wallet, _| {
                        hardware.sign_transaction(wallet, &path, &message)
                    })
                });
                let _ = reply.send(result);
            }

            DeviceCommand::SignOffchainMessage {
                claim: _claim,
                path_str,
                message,
                binding,
                pubkey,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    sessions.run(&binding, &path, &pubkey, |hardware, wallet, _| {
                        hardware.sign_offchain(wallet, &path, &message)
                    })
                });
                let _ = reply.send(result);
            }

            DeviceCommand::IsAvailable {
                claim: _claim,
                path_str,
                binding,
                pubkey,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    sessions.run(&binding, &path, &pubkey, |hardware, wallet, checked| {
                        checked.map_or_else(|| hardware.pubkey(wallet, &path, false), Ok)
                    })
                });
                let _ = reply.send(result);
            }

            DeviceCommand::IsAttached { reply } => {
                let _ = reply.send(sessions.hardware.is_attached());
            }

            DeviceCommand::Release => sessions.release(),
        }
    }
}

/// The device thread's open sessions, keyed by the host path each was opened at.
struct Sessions<H: Hardware> {
    hardware: H,
    open: HashMap<String, Session<H::Wallet>>,
    /// The signers that have used each host path. Kept apart from `open` so a
    /// rebuilt session stays bound to them; dead ones are pruned on release.
    bound: HashMap<String, Vec<Weak<Binding>>>,
}

/// An open device handle and the signers that have run on it since it opened.
struct Session<W> {
    wallet: W,
    ran: Vec<Weak<Binding>>,
}

impl<W> Session<W> {
    fn has_run(&self, binding: &Arc<Binding>) -> bool {
        self.ran
            .iter()
            .any(|ran| ran.as_ptr() == Arc::as_ptr(binding))
    }
}

impl<H: Hardware> Sessions<H> {
    /// The host paths of `binding`'s device's interfaces, the one it selected
    /// first; it runs on [`Binding::openable`]. A named binding uses the
    /// open session at its path or the one it last ran on; a `None` binding
    /// uses the one it last ran on. Otherwise this lists the interfaces of the
    /// named device, or of the sole one, with that listing. A connect's binding
    /// is new and has run on no session, so an unnamed connect always lists.
    fn targets(&self, binding: &Binding) -> Result<(Vec<String>, Option<H::Listing>), SignerError> {
        let held = match &binding.host_device_path {
            Some(path) => Some(path)
                .filter(|path| self.open.contains_key(*path))
                .or_else(|| self.last_run_on(binding)),
            None => self.last_run_on(binding),
        };
        if let Some(key) = held {
            return Ok((vec![key.clone()], None));
        }
        let listing = self.hardware.list()?;
        let targets = self
            .hardware
            .resolve(&listing, binding.host_device_path.as_deref())?;
        Ok((targets, Some(listing)))
    }

    /// The open session `binding` last ran on.
    fn last_run_on(&self, binding: &Binding) -> Option<&String> {
        self.bound
            .iter()
            .find(|(_, bound)| {
                bound
                    .iter()
                    .any(|bound| std::ptr::eq(bound.as_ptr(), binding))
            })
            .map(|(key, _)| key)
            .filter(|key| self.open.contains_key(*key))
    }

    /// Run `f` against the session for `binding`'s device, opening it if it is
    /// gone.
    ///
    /// Re-establishes against the host path this signer was opened with.
    /// Refuses a session `binding` did not already run on unless its key at
    /// `path` is `pubkey`, so another device is never prompted. Re-establishes
    /// without dashboard auto-launch: signing is not the moment to drive app
    /// management. `f` gets the key that check read, if it read one.
    fn run<T>(
        &mut self,
        binding: &Arc<Binding>,
        path: &DerivationPath,
        pubkey: &[u8; 32],
        f: impl FnOnce(&H, &H::Wallet, Option<[u8; 32]>) -> Result<T, SignerError>,
    ) -> Result<T, SignerError> {
        let (interfaces, listing) = self.targets(binding)?;
        let targets = binding.openable(&interfaces);
        let held = targets
            .iter()
            .find(|key| self.open.contains_key(*key))
            .cloned();
        let key = match &held {
            Some(key) => key.clone(),
            None => self.open_first(
                targets,
                listing.as_ref(),
                binding.host_device_path.as_deref(),
            )?,
        };
        let ran_here = held.is_some() && self.open[&key].has_run(binding);
        let mut checked = None;
        if !ran_here {
            let read = self.hardware.pubkey(&self.open[&key].wallet, path, false);
            checked = read.as_ref().ok().copied();
            if read.as_ref().ok() != Some(pubkey) {
                if held.is_none()
                    || read
                        .as_ref()
                        .is_err_and(|error| session_action(error) == SessionAction::Drop)
                {
                    self.open.remove(&key);
                }
                return Err(read.err().unwrap_or_else(another_device_error));
            }
        }
        self.run_on(&[key], None, binding, |hardware, wallet| {
            f(hardware, wallet, checked)
        })
    }

    /// Run `f` against the first of `targets` with an open session, or else
    /// the first that opens.
    fn run_on<T>(
        &mut self,
        targets: &[String],
        listing: Option<&H::Listing>,
        binding: &Arc<Binding>,
        f: impl FnOnce(&H, &H::Wallet) -> Result<T, SignerError>,
    ) -> Result<T, SignerError> {
        let key = match targets.iter().find(|key| self.open.contains_key(*key)) {
            Some(key) => key.clone(),
            None => self.open_first(targets, listing, binding.host_device_path.as_deref())?,
        };
        if !self.bound.get(&key).is_some_and(|bound| {
            bound
                .iter()
                .any(|bound| bound.as_ptr() == Arc::as_ptr(binding))
        }) {
            // A `None` binding whose device re-resolved leaves its old path.
            for bound in self.bound.values_mut() {
                bound.retain(|bound| bound.as_ptr() != Arc::as_ptr(binding));
            }
            self.bound
                .entry(key.clone())
                .or_default()
                .push(Arc::downgrade(binding));
            self.release();
        }
        let session = self.open.get_mut(&key).expect("held or just opened");

        let result = f(&self.hardware, &session.wallet);
        let dropped = result
            .as_ref()
            .is_err_and(|error| session_action(error) == SessionAction::Drop);
        if dropped {
            self.open.remove(&key);
        } else if !session.has_run(binding) {
            session.ran.push(Arc::downgrade(binding));
        }
        result
    }

    /// Open the first of `targets` that opens, in `listing` or else a new one.
    /// Fails with the most specific failure: locked, then not listed, then any
    /// other. Not listed names only `named`, the path the caller gave.
    fn open_first(
        &mut self,
        targets: &[String],
        listing: Option<&H::Listing>,
        named: Option<&str>,
    ) -> Result<String, SignerError> {
        let listed;
        let listing = match listing {
            Some(listing) => listing,
            None => {
                listed = self.hardware.list()?;
                &listed
            }
        };
        let mut failed: Option<(u8, SignerError)> = None;
        for key in targets {
            let (rank, error) = match self.hardware.open(listing, key) {
                Ok(Some((opened, wallet))) => {
                    self.open.insert(
                        opened.clone(),
                        Session {
                            wallet,
                            ran: Vec::new(),
                        },
                    );
                    return Ok(opened);
                }
                Ok(None) => match named {
                    Some(want) => (1, no_device_at(want)),
                    None => {
                        #[cfg(feature = "unsafe-debug")]
                        log::error!("no Ledger listed at `{key}` any more");
                        (1, self.hardware.unenumerated())
                    }
                },
                Err(error) if matches!(&error, SignerError::NotAvailable(d) if d == LOCKED_DETAIL) => {
                    (2, error)
                }
                Err(error) => (0, error),
            };
            if failed.as_ref().is_none_or(|(kept, _)| rank > *kept) {
                failed = Some((rank, error));
            }
        }
        Err(failed.map_or_else(|| self.hardware.unenumerated(), |(_, error)| error))
    }

    /// Read the pubkey a new signer caches. A `None` binding always lists
    /// devices, so it refuses while more than one Ledger is attached. An
    /// on-screen confirmation always reaches the device on a fresh session;
    /// otherwise a held session is reused, and rebuilt once if it has gone stale.
    fn connect(
        &mut self,
        binding: &Arc<Binding>,
        path: &DerivationPath,
        confirm_pubkey_on_device: bool,
        auto_open_app: bool,
    ) -> Result<[u8; 32], SignerError> {
        let read = |hardware: &H, wallet: &H::Wallet| {
            hardware.pubkey(wallet, path, confirm_pubkey_on_device)
        };
        let (mut interfaces, mut listing) = self.targets(binding)?;
        if confirm_pubkey_on_device {
            self.close_device(binding, &mut interfaces, &mut listing)?;
        }
        let targets = binding.openable(&interfaces);
        let held = targets.iter().any(|key| self.open.contains_key(key));
        let mut connected = self.run_on(targets, listing.as_ref(), binding, read);
        if held
            && connected
                .as_ref()
                .is_err_and(|error| session_action(error) == SessionAction::Drop)
        {
            connected = self.run_on(targets, listing.as_ref(), binding, read);
        }

        // The Solana app may simply not be running. Once the user
        // has unlocked with their PIN, auto-launch it for them via
        // the BOLOS dashboard instead of erroring out with "open the
        // Solana app", then retry across the USB re-enumeration that
        // launching an app triggers. Best-effort: if the dashboard is
        // unreachable we keep the original connect error. Declining
        // the launch prompt on-device, though, is a real user
        // decision — surface it.
        if auto_open_app
            && connected
                .as_ref()
                .is_err_and(|error| session_action(error) == SessionAction::Drop)
        {
            if let Err(e) = self.close_device(binding, &mut interfaces, &mut listing) {
                log::debug!(
                    "could not list the Ledger's interfaces ({e:?}); returning the connect error"
                );
                return connected;
            }
            match self
                .hardware
                .launch_app(binding.host_device_path.as_deref())
            {
                // The dashboard can identify a locked device exactly
                // (APDU 0x5515) where the Solana-app path cannot. When
                // it does, prefer that definitive answer over the
                // hedged "locked or busy" one the connect produced.
                Err(e @ SignerError::NotAvailable(_))
                    if e.detail_string().contains("is locked") =>
                {
                    return Err(e)
                }
                Ok(false) => {}
                Ok(true) => {
                    for _ in 0..20 {
                        self.hardware.settle();
                        connected = self.targets(binding).and_then(|(interfaces, listing)| {
                            let targets = binding.openable(&interfaces);
                            self.run_on(targets, listing.as_ref(), binding, read)
                        });
                        if !connected
                            .as_ref()
                            .is_err_and(|error| session_action(error) == SessionAction::Drop)
                        {
                            break;
                        }
                    }
                }
                Err(e @ SignerError::UserRejected(_)) => return Err(e),
                Err(e) => log::debug!("could not auto-open the Solana app ({e:?}); continuing"),
            }
        }
        connected
    }

    /// Close every open session on an interface of `binding`'s device. A held
    /// session's `interfaces` name its path alone, so this lists them first.
    fn close_device(
        &mut self,
        binding: &Binding,
        interfaces: &mut Vec<String>,
        listing: &mut Option<H::Listing>,
    ) -> Result<(), SignerError> {
        if listing.is_none() {
            let listed = self.hardware.list()?;
            *interfaces = self
                .hardware
                .resolve(&listed, binding.host_device_path.as_deref())?;
            *listing = Some(listed);
        }
        self.open.retain(|key, _| !interfaces.contains(key));
        Ok(())
    }

    /// Close every session no live signer is bound to.
    fn release(&mut self) {
        self.bound.retain(|_, bound| {
            bound.retain(|bound| bound.strong_count() > 0);
            !bound.is_empty()
        });
        self.open.retain(|key, session| {
            session.ran.retain(|ran| ran.strong_count() > 0);
            self.bound.contains_key(key)
        });
    }
}

/// What an error means for the cached device session.
#[derive(Debug, PartialEq, Eq)]
enum SessionAction {
    /// The transport is fine; keep the handle.
    Keep,
    /// The transport or the device state is suspect; rebuild on next use.
    Drop,
}

/// Decide whether an error should cost us the session.
///
/// Rejections are app-level answers over a healthy transport and must not
/// discard the session. Only availability and signing faults mean the handle
/// is worthless (device gone, locked, held by another process, or in a
/// different app).
fn session_action(error: &SignerError) -> SessionAction {
    match error {
        SignerError::NotAvailable(_) | SignerError::SigningFailed(_) => SessionAction::Drop,
        // UserRejected above all, plus ConfigError, which never reached the wire.
        _ => SessionAction::Keep,
    }
}

/// Extract the 64 raw bytes of a `solana-remote-wallet` signature so it can be
/// rebuilt as the SDK-version-selected [`Signature`] type (byte-level bridge —
/// no cross-version type unification required).
///
/// Taken as `impl AsRef<[u8]>` rather than naming `solana_signature::Signature`:
/// under `sdk-v4` the `solana-signature` crate is bundled inside `solana-sdk`
/// and is not a direct dependency to name.
fn signature_bytes(sig: impl AsRef<[u8]>) -> Result<[u8; 64], SignerError> {
    let raw = sig.as_ref();
    // `copy_from_slice` panics on a length mismatch, and this length comes from
    // the device. An ed25519 signature is always 64 bytes, so a short read here
    // means the transport handed us a truncated response -- exactly the case
    // where aborting the caller's process is the wrong answer, and exactly the
    // case a hardware backend has to expect. Fails closed instead: nothing was
    // signed that anyone can use.
    raw.try_into().map_err(|_| {
        #[cfg(feature = "unsafe-debug")]
        log::error!(
            "Ledger returned a {}-byte signature; ed25519 is 64",
            raw.len()
        );
        SignerError::SigningFailed(
            "the Ledger returned a signature of the wrong length, so the response was \
             truncated in transit. Nothing was signed. Retry, and if it persists run \
             `just rust-ledger-diagnose`."
                .to_string(),
        )
    })
}

/// Appended to HID-layer failures on Linux.
///
/// On Linux a Ledger is invisible to a non-root process until udev rules grant
/// the user access, and the failure surfaces as a plain HID open error that
/// looks identical to a disconnected cable. Without naming udev, the user is
/// sent to check hardware that is working fine. Empty on every other platform,
/// where no such rules exist.
#[cfg(target_os = "linux")]
const LINUX_UDEV_HINT: &str = " On Linux this is most often missing udev rules: \
     without them the device node is not readable by your user. See the \
     \"Linux: udev rules\" section of the Ledger backend documentation.";

/// Not applicable off Linux.
#[cfg(not(target_os = "linux"))]
const LINUX_UDEV_HINT: &str = "";

/// Map `solana-remote-wallet` errors onto [`SignerError`], preserving the
/// user-rejection and device-absence cases the caller wants to distinguish.
fn map_rw_err(e: RemoteWalletError) -> SignerError {
    use solana_remote_wallet::ledger_error::LedgerError;
    match e {
        // Two distinct "cancel"s: the host-side `UserCancel`, and the device
        // returning APDU status 0x6985 (`LedgerError::UserCancel`) when the
        // user rejects on-screen. A real on-device decline is the latter.
        RemoteWalletError::UserCancel | RemoteWalletError::LedgerError(LedgerError::UserCancel) => {
            SignerError::UserRejected("request rejected on Ledger device".to_string())
        }
        RemoteWalletError::NoDeviceFound => {
            SignerError::NotAvailable("no Ledger device found".to_string())
        }
        // A HID-layer failure is usually *not* a disconnect. The common cause is
        // another process already holding the device: Ledger Live keeps its
        // handle for as long as it runs, and so does any wallet tool or stray
        // script that opened the device and never exited. Naming only the
        // disconnect sends the user to check the cable, which is the one thing
        // that is fine.
        RemoteWalletError::Hid(_) => SignerError::NotAvailable(format!(
            "Ledger is not reachable. Either it was disconnected, or another application is \
             holding the device — quit Ledger Live and any other wallet software, then \
             retry.{}",
            LINUX_UDEV_HINT
        )),
        // Protocol error: device is locked or another process holds it (both on Nano Gen5
        // produce `Protocol("Unknown error")`), or app-protocol incompatibility
        // (GET_APP_CONFIGURATION returns 7 bytes vs. 5 expected). Cannot distinguish here;
        // must name both causes to avoid sending users to unlock already-unlocked devices.
        RemoteWalletError::Protocol(detail) if detail.contains("Version packet") => {
            log::error!(
                "The Ledger's Solana app returned an app-configuration vector this \
                 solana-remote-wallet cannot parse. This is an upstream version \
                 incompatibility, not a device problem: the device is fine and no \
                 amount of unlocking or replugging will help. Run \
                 `just rust-ledger-diagnose` to capture the exact bytes."
            );
            SignerError::NotAvailable(
                "the Ledger's Solana app speaks a configuration format this build of \
                 solana-remote-wallet cannot parse, so it will not enumerate the device. \
                 The device is not at fault. This needs a newer solana-remote-wallet (or an \
                 older Solana app); see the backend README."
                    .to_string(),
            )
        }
        RemoteWalletError::Protocol(_) => {
            // `SignerError` Display and Debug are both redacted by design, and
            // `detail_string` is crate-private, so an external caller cannot
            // read the remedy out of the error. Log it: this particular detail
            // is device state, not secret material, and without it the user just
            // sees "Signer not available" with nothing to act on.
            log::warn!(
                "Ledger did not answer an app-level command. It is either locked, or another \
                 application is holding the device. Unlock it and open the Solana app, or quit \
                 Ledger Live and any other wallet software, then retry."
            );
            SignerError::NotAvailable(LOCKED_DETAIL.to_string())
        }
        // APDU 0x6808 (Nano Gen5 with Solana app 1.16.0): off-chain message with
        // non-ASCII payload when blind signing is disabled. Mirrors the device's
        // "This transaction cannot be clear-signed" prompt; the modal must be
        // dismissed before the device answers anything else.
        RemoteWalletError::LedgerError(LedgerError::SdkNotSupported) => SignerError::SigningFailed(
            "the Ledger could not clear-sign this, and blind signing is disabled in the \
                 Solana app's settings. The device shows \"This transaction cannot be \
                 clear-signed\" with a \"Go to settings\" prompt, which has to be dismissed \
                 before it will answer anything else. Blind signing is required for off-chain \
                 messages that are not printable ASCII, and for transactions the app cannot \
                 decode."
                .to_string(),
        ),
        other => {
            // The catch-all. Whatever upstream put in it is device state at
            // best and an opaque transport string at worst, so it goes to the
            // log and the caller gets a stable message.
            #[cfg(feature = "unsafe-debug")]
            log::error!("Ledger device error: {other}");
            #[cfg(not(feature = "unsafe-debug"))]
            let _ = other;
            SignerError::SigningFailed(
                "the Ledger reported an error while signing. Nothing was signed. Run \
                 `just rust-ledger-diagnose` to capture what the device says about itself."
                    .to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// `DEVICE_BUSY` is process-global, so the tests that drive it cannot run
    /// concurrently with each other.
    static BUSY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A device thread that accepts commands and never answers, which is what a
    /// Ledger left on a confirm screen looks like from the host.
    fn wedged_actor() -> (Sender<DeviceCommand>, Receiver<DeviceCommand>) {
        mpsc::channel()
    }

    fn connect_cmd(
        claim: DeviceClaim,
        reply: Sender<Result<[u8; 32], SignerError>>,
    ) -> DeviceCommand {
        DeviceCommand::Connect {
            claim,
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            confirm_pubkey_on_device: false,
            binding: Arc::new(Binding {
                host_device_path: None,
                release: mpsc::channel().0,
            }),
            auto_open_app: false,
            reply,
        }
    }

    #[test]
    fn a_command_times_out_at_its_tier_deadline() {
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DEVICE_BUSY.store(false, Ordering::SeqCst);
        // The receiver is held so `send` succeeds, but nothing ever serves it.
        let (tx, _rx) = wedged_actor();
        let start = Instant::now();
        let err = request_on(
            &tx,
            Duration::from_millis(200),
            DeviceClaim::acquire().unwrap(),
            connect_cmd,
        )
        .unwrap_err();
        assert!(
            start.elapsed() >= Duration::from_millis(200),
            "must honour the deadline"
        );
        assert!(start.elapsed() < Duration::from_secs(5), "must not hang");
        assert!(
            err.detail_string().contains("busy with another operation"),
            "the timeout must be distinguishable from a plain no-device error, got: {}",
            err.detail_string()
        );
    }

    #[test]
    fn a_second_signing_request_fails_fast_while_the_device_is_busy() {
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Someone is standing at the confirm screen.
        DEVICE_BUSY.store(true, Ordering::SeqCst);
        let start = Instant::now();
        let busy = device_is_busy();
        DEVICE_BUSY.store(false, Ordering::SeqCst);
        assert!(busy, "the flag must report the in-flight command");
        assert!(start.elapsed() < Duration::from_millis(50));
        // And the error a caller gets says so, rather than looking like an
        // unplugged device.
        let err = busy_error();
        assert!(matches!(err, SignerError::NotAvailable(_)));
        assert!(err
            .detail_string()
            .contains("awaiting on-device confirmation"));
    }

    #[test]
    fn a_claim_is_exclusive_and_released_on_drop() {
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DEVICE_BUSY.store(false, Ordering::SeqCst);

        let claim = DeviceClaim::acquire().expect("idle device must be claimable");
        assert!(device_is_busy());
        // A second claim must fail rather than wait.
        assert!(DeviceClaim::acquire().is_err());
        assert!(DeviceClaim::try_acquire().is_none());
        drop(claim);
        assert!(
            !device_is_busy(),
            "dropping must release, or the device wedges"
        );
        assert!(DeviceClaim::acquire().is_ok());
        DEVICE_BUSY.store(false, Ordering::SeqCst);
    }

    #[test]
    fn exactly_one_of_many_racing_claims_wins() {
        // Many threads, one shared device, repeatedly. If admission is not
        // atomic, more than one thread holds a claim simultaneously.
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DEVICE_BUSY.store(false, Ordering::SeqCst);

        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc as StdArc;
        static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
        let max_seen = StdArc::new(AtomicUsize::new(0));
        let wins = StdArc::new(AtomicUsize::new(0));
        let start = StdArc::new(std::sync::Barrier::new(8));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let max_seen = StdArc::clone(&max_seen);
            let wins = StdArc::clone(&wins);
            let start = StdArc::clone(&start);
            handles.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..500 {
                    if let Some(claim) = DeviceClaim::try_acquire() {
                        wins.fetch_add(1, Ordering::SeqCst);
                        let n = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(n, Ordering::SeqCst);
                        std::thread::yield_now();
                        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                        drop(claim);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("no thread should panic");
        }

        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "two callers held the device at once; admission is not atomic"
        );
        assert!(
            wins.load(Ordering::SeqCst) > 0,
            "the test proved nothing if nobody ever acquired"
        );
        assert!(!device_is_busy(), "every claim must have been released");
        DEVICE_BUSY.store(false, Ordering::SeqCst);
    }

    #[test]
    fn a_caller_timeout_does_not_release_the_device() {
        // The claim is moved into the command and dropped by the actor when the
        // work finishes. A wedged actor never drops it, so it stays held.
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DEVICE_BUSY.store(false, Ordering::SeqCst);

        // `_rx` is held so the send succeeds and nothing ever serves it: a
        // wedged actor.
        let (tx, _rx) = wedged_actor();
        let claim = DeviceClaim::acquire().expect("idle");
        let err = request_on(&tx, Duration::from_millis(150), claim, connect_cmd).unwrap_err();
        assert!(err.detail_string().contains("busy with another operation"));

        assert!(
            device_is_busy(),
            "the caller timed out but the actor is still blocked, so the device \
             must stay claimed"
        );
        assert!(
            DeviceClaim::acquire().is_err(),
            "a later caller must fail fast, not queue behind the wedged actor"
        );

        // Draining the command drops the claim, which is what the actor does
        // once the device work completes.
        drop(_rx);
        assert!(!device_is_busy(), "the claim releases with the command");
        DEVICE_BUSY.store(false, Ordering::SeqCst);
    }

    #[test]
    fn an_abandoned_reply_channel_does_not_panic_the_actor() {
        // A caller that timed out has dropped its receiver. The actor answers
        // into a dead channel; `let _ = reply.send(..)` must swallow that. If it
        // ever became an unwrap, one timeout would kill the device thread for
        // the whole process.
        let (reply_tx, reply_rx) = mpsc::channel::<Result<bool, SignerError>>();
        drop(reply_rx);
        let _ = reply_tx.send(Ok(true));
    }

    #[test]
    fn a_rejection_keeps_the_session_and_a_transport_fault_drops_it() {
        // A rejection is an app-level answer over a healthy transport and must
        // not discard the session.
        assert_eq!(
            session_action(&SignerError::UserRejected("declined".into())),
            SessionAction::Keep,
            "a decline is an app-level answer, not a transport fault"
        );
        // These are what map_rw_err produces for a device that is gone, locked,
        // held by another process, or in a different app. The handle is worthless.
        assert_eq!(
            session_action(&SignerError::NotAvailable("gone".into())),
            SessionAction::Drop
        );
        assert_eq!(
            session_action(&SignerError::SigningFailed("device error".into())),
            SessionAction::Drop
        );
        // Never reached the wire.
        assert_eq!(
            session_action(&SignerError::ConfigError("bad path".into())),
            SessionAction::Keep
        );
    }

    #[test]
    fn the_real_rejection_error_keeps_the_session() {
        // Guard the mapping end to end rather than the variant in isolation:
        // both of remote-wallet's cancel shapes must come out as Keep.
        use solana_remote_wallet::ledger_error::LedgerError;
        for raw in [
            RemoteWalletError::UserCancel,
            RemoteWalletError::LedgerError(LedgerError::UserCancel),
        ] {
            let mapped = map_rw_err(raw);
            assert_eq!(
                session_action(&mapped),
                SessionAction::Keep,
                "an on-device decline must not cost the session"
            );
        }
    }

    #[test]
    fn a_signer_remembers_the_device_it_was_opened_against() {
        // Needed so a lost session re-establishes against the same Ledger
        // instead of whichever one happens to be attached. Constructed directly
        // because `connect` needs hardware; this pins the field's contract.
        let bound_to = |host_device_path: Option<&str>| {
            Arc::new(Binding {
                host_device_path: host_device_path.map(str::to_string),
                release: mpsc::channel().0,
            })
        };
        let signer = LedgerSigner {
            pubkey: Pubkey::from([1u8; 32]),
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            binding: bound_to(Some("/dev/hidraw3")),
            signing_timeout: DEFAULT_SIGN_TIMEOUT,
        };
        assert_eq!(signer.host_device_path(), Some("/dev/hidraw3"));

        let sole = LedgerSigner {
            pubkey: Pubkey::from([2u8; 32]),
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            binding: bound_to(None),
            signing_timeout: DEFAULT_SIGN_TIMEOUT,
        };
        assert_eq!(sole.host_device_path(), None);
    }

    #[test]
    fn docs_quote_the_real_timeout_constants() {
        // Doc must reference constants, not hardcoded values; no bare cargo commands.
        let doc = include_str!("README.md");
        for stale in [
            "5-minute signing timeout",
            "300s",
            "FAST_COMMAND_TIMEOUT",
            "cargo ",
        ] {
            assert!(
                !doc.contains(stale),
                "rust/src/ledger/README.md still contains `{stale}`, which no longer matches the code"
            );
        }
        for named in ["OPS_TIMEOUT", "DEFAULT_SIGN_TIMEOUT"] {
            assert!(
                doc.contains(named),
                "rust/src/ledger/README.md should name `{named}` rather than restate its value"
            );
        }
        // And the constants the doc names really are the public ones.
        assert_eq!(OPS_TIMEOUT, Duration::from_secs(10));
        assert_eq!(DEFAULT_SIGN_TIMEOUT, Duration::from_secs(120));
    }

    #[test]
    fn the_two_timeout_tiers_are_ordered_and_bounded() {
        // A probe that cannot involve the user must not inherit the
        // wait-for-a-human budget, and the signing default must stay inside a
        // Ledger's ten-minute auto-lock: past that the prompt is gone and no
        // answer is coming.
        assert!(OPS_TIMEOUT < DEFAULT_SIGN_TIMEOUT);
        assert!(OPS_TIMEOUT >= Duration::from_secs(5));
        assert!(DEFAULT_SIGN_TIMEOUT <= Duration::from_secs(600));
        assert_eq!(
            LedgerConfig::default().signing_timeout,
            DEFAULT_SIGN_TIMEOUT
        );
    }

    #[test]
    fn auto_open_app_defaults_on_and_is_overridable() {
        // Default true keeps the interactive CLI behaviour these tests were
        // written against; the point of the option is unattended callers.
        assert!(LedgerConfig::default().auto_open_app);
        let quiet = LedgerConfig {
            auto_open_app: false,
            ..LedgerConfig::default()
        };
        assert!(!quiet.auto_open_app);
    }

    // NOTE: the `Rig` tests below drive `sign_message` through the real
    // `device_thread` over `FakeHardware`; the device itself is covered by the
    // hardware integration test (see `tests/test_ledger_integration.rs`).

    /// Two distinct keys, standing in for two physically different Ledgers.
    fn device_key(seed: u8) -> (crate::sdk_adapter::Keypair, Pubkey) {
        let kp = crate::sdk_adapter::keypair_from_seed(&[seed; 32]).expect("valid seed");
        let pubkey = crate::sdk_adapter::keypair_pubkey(&kp);
        (kp, pubkey)
    }

    #[test]
    fn a_swapped_device_is_caught_as_a_verification_failure() {
        // The race this closes: `LedgerSigner` caches a pubkey at connect, but
        // the actor's cached session is keyed on the host path, not on the
        // signer. If a second `connect` re-points the session at a different
        // device, an existing signer's next command runs against *that* device.
        //
        // The signature then comes back from the wrong key. Because every
        // signature is verified against the pubkey cached at connect, and never
        // against whatever the device reports now, this surfaces as a clean
        // rejection instead of a wrong-key signature being attached.
        let (device_a, pubkey_a) = device_key(1);
        let (device_b, pubkey_b) = device_key(2);
        assert_ne!(pubkey_a, pubkey_b);

        let envelope = ledger_offchain_envelope(&pubkey_a, b"transfer 1 SOL").unwrap();
        // The swapped-in device signs the bytes we sent, with its own key.
        let from_b = crate::sdk_adapter::keypair_sign_message(&device_b, &envelope);

        let err = crate::signature_util::verify_or_reject(&from_b, &pubkey_a, &envelope)
            .expect_err("a signature from a swapped device must never be attached");
        assert!(matches!(err, SignerError::SigningFailed(_)));

        // Control: the device we actually connected to is accepted.
        let from_a = crate::sdk_adapter::keypair_sign_message(&device_a, &envelope);
        assert!(crate::signature_util::verify_or_reject(&from_a, &pubkey_a, &envelope).is_ok());
    }

    #[test]
    fn a_corrupted_signature_is_rejected_on_the_offchain_path() {
        // Transport corruption on the off-chain path. The bytes verified are the
        // envelope, not the payload, which is the whole reason this check has to
        // be built from `ledger_offchain_envelope` and not from the raw message.
        let (device, pubkey) = device_key(3);
        let envelope = ledger_offchain_envelope(&pubkey, b"hello").unwrap();
        let good = crate::sdk_adapter::keypair_sign_message(&device, &envelope);
        assert!(crate::signature_util::verify_or_reject(&good, &pubkey, &envelope).is_ok());

        let mut raw = signature_bytes(good).expect("64 bytes");
        raw[0] ^= 0x01;
        let corrupted = Signature::from(raw);
        assert!(
            crate::signature_util::verify_or_reject(&corrupted, &pubkey, &envelope).is_err(),
            "a single flipped bit must fail verification"
        );
    }

    #[test]
    fn a_corrupted_signature_is_rejected_on_the_transaction_path() {
        // Same guarantee on the transaction path, over the exact bytes that
        // cross to the device: `tx.message.serialize()`.
        let (device, pubkey) = device_key(4);
        let tx = crate::test_util::create_test_transaction(&pubkey);
        let message = tx.message.serialize();
        let good = crate::sdk_adapter::keypair_sign_message(&device, &message);
        assert!(crate::signature_util::verify_or_reject(&good, &pubkey, &message).is_ok());

        let mut raw = signature_bytes(good).expect("64 bytes");
        raw[63] ^= 0x80;
        let corrupted = Signature::from(raw);
        assert!(
            crate::signature_util::verify_or_reject(&corrupted, &pubkey, &message).is_err(),
            "a single flipped bit must fail verification"
        );
    }

    /// Test-only override for [`command_channel`], so the signing paths can be
    /// driven against a device we control. `None` in production, and there is
    /// no production code that can set it.
    pub(super) static CHANNEL_OVERRIDE: std::sync::Mutex<Option<Sender<DeviceCommand>>> =
        std::sync::Mutex::new(None);

    /// A fake Ledger, and the signing paths pointed at it.
    ///
    /// Answers the two signing commands the way a device does -- signing the
    /// exact bytes it was handed -- and optionally flips one bit of the result,
    /// which is what transport corruption or a swapped device looks like from
    /// the host. Clears the override and drains the actor on drop, by every exit
    /// path including a panicking assertion, so one failing test cannot leak a
    /// fake device into the rest of the suite.
    struct FakeDevice {
        _guard: std::sync::MutexGuard<'static, ()>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeDevice {
        fn attach(seed: u8, corrupt: bool) -> (Self, Pubkey) {
            let guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            DEVICE_BUSY.store(false, Ordering::SeqCst);

            let (kp, pubkey) = device_key(seed);
            let (tx, rx) = mpsc::channel::<DeviceCommand>();
            let thread = std::thread::spawn(move || {
                // One command at a time, exactly like the real actor. Each
                // command is dropped at the end of its iteration, which is what
                // releases the `DeviceClaim`.
                while let Ok(cmd) = rx.recv() {
                    match cmd {
                        DeviceCommand::SignOffchainMessage { message, reply, .. }
                        | DeviceCommand::SignTransactionMessage { message, reply, .. } => {
                            let sig = crate::sdk_adapter::keypair_sign_message(&kp, &message);
                            let mut raw = signature_bytes(sig).expect("64 bytes");
                            if corrupt {
                                raw[0] ^= 0x01;
                            }
                            let _ = reply.send(Ok(raw));
                        }
                        DeviceCommand::Connect { reply, .. } => {
                            let _ = reply.send(Ok(pubkey.to_bytes()));
                        }
                        DeviceCommand::IsAvailable { reply, .. } => {
                            let _ = reply.send(Ok(pubkey.to_bytes()));
                        }
                        DeviceCommand::IsAttached { reply } => {
                            let _ = reply.send(true);
                        }
                        DeviceCommand::Release => {}
                    }
                }
            });

            *CHANNEL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
            (
                Self {
                    _guard: guard,
                    thread: Some(thread),
                },
                pubkey,
            )
        }
    }

    impl Drop for FakeDevice {
        fn drop(&mut self) {
            // Dropping the sender ends the actor loop.
            *CHANNEL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = None;
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            DEVICE_BUSY.store(false, Ordering::SeqCst);
        }
    }

    fn signer_for(pubkey: Pubkey) -> LedgerSigner {
        LedgerSigner {
            pubkey,
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            binding: Arc::new(Binding {
                host_device_path: None,
                release: command_channel(),
            }),
            signing_timeout: Duration::from_secs(5),
        }
    }

    /// A device whose signature does not verify must be refused on the off-chain
    /// path. Tests against a controlled device that corruption is caught.
    #[tokio::test]
    async fn a_corrupted_device_signature_is_refused_by_sign_message() {
        let (_device, pubkey) = FakeDevice::attach(11, true);
        let signer = signer_for(pubkey);
        let err = signer
            .sign_message(b"pay 1 SOL")
            .await
            .expect_err("a signature that does not verify must never be returned");
        assert!(matches!(err, SignerError::SigningFailed(_)), "got: {err:?}");
    }

    /// The control for the test above: the same path, the same fake device, an
    /// uncorrupted signature. Without this, a `sign_message` that failed for any
    /// unrelated reason would satisfy the assertion above.
    #[tokio::test]
    async fn an_honest_device_signature_is_returned_by_sign_message() {
        let (_device, pubkey) = FakeDevice::attach(12, false);
        let signer = signer_for(pubkey);
        let signature = signer
            .sign_message(b"pay 1 SOL")
            .await
            .expect("an honest signature must be returned");
        // And it covers the envelope, which is the contract this path has.
        let envelope = ledger_offchain_envelope(&pubkey, b"pay 1 SOL").unwrap();
        assert!(crate::signature_util::verify_or_reject(&signature, &pubkey, &envelope).is_ok());
    }

    /// Same guarantee on the transaction path.
    #[tokio::test]
    async fn a_corrupted_device_signature_is_refused_by_sign_transaction() {
        let (_device, pubkey) = FakeDevice::attach(13, true);
        let signer = signer_for(pubkey);
        let mut tx = crate::test_util::create_test_transaction(&pubkey);
        let err = signer
            .sign_transaction(&mut tx)
            .await
            .expect_err("a signature that does not verify must never be attached");
        assert!(matches!(err, SignerError::SigningFailed(_)), "got: {err:?}");
        // And nothing was attached to the caller's transaction on the way out.
        assert!(
            tx.signatures.iter().all(|s| *s == Signature::default()),
            "a rejected signature must not be written into the transaction"
        );
    }

    /// Control for the transaction path.
    #[tokio::test]
    async fn an_honest_device_signature_is_attached_by_sign_transaction() {
        let (_device, pubkey) = FakeDevice::attach(14, false);
        let signer = signer_for(pubkey);
        let mut tx = crate::test_util::create_test_transaction(&pubkey);
        // Captured before signing: these are the bytes that cross to the
        // device, and the ones the returned signature must cover.
        let message = tx.message.serialize();
        let result = signer
            .sign_transaction(&mut tx)
            .await
            .expect("an honest signature must be attached");
        let (_serialized, signature) = result.into_signed_transaction();
        assert_eq!(tx.signatures[0], signature);
        assert!(crate::signature_util::verify_or_reject(&signature, &pubkey, &message).is_ok());
    }

    /// What the fake Ledgers do, shared between a test and the device thread
    /// it drives.
    #[derive(Default)]
    struct Bench {
        /// The attached devices, each as its interfaces' host paths.
        attached: Vec<Vec<String>>,
        /// The serial every interface reports, as every Nano Gen5 reports "0001".
        serial: Option<&'static str>,
        /// Every hardware call, in order, as `"<call> <host path>"`.
        calls: Vec<String>,
        /// How many times the attached devices were listed.
        listings: usize,
        /// Listings past this many fail.
        unlisted_after: Option<usize>,
        /// Devices whose next call fails the way a lost device does.
        faulty: Vec<String>,
        /// Devices whose next prompt the user declines.
        declined: Vec<String>,
        /// Devices that open but fail the device read, as a locked one does.
        locked: Vec<String>,
        /// Devices listed that another application holds, so they do not open.
        held_elsewhere: Vec<String>,
        /// Devices unplugged between being listed and opened.
        vanished: Vec<String>,
        /// Devices that hold another path's key, as host path to that path.
        keys: HashMap<String, String>,
        /// Where the attached device re-enumerates once its app launches.
        relaunched_at: Option<String>,
        /// The Solana app already runs, so a launch has nothing to do.
        app_running: bool,
        /// Holds the next signature at its prompt: reports reaching it, then
        /// waits for an answer or for the answering side to drop.
        prompt: Option<(Sender<()>, Receiver<()>)>,
    }

    #[derive(Clone)]
    struct FakeHardware(Arc<std::sync::Mutex<Bench>>);

    /// A fake device handle that logs its close, so a test sees a session end.
    struct FakeWallet {
        host_path: String,
        hardware: FakeHardware,
    }

    impl Drop for FakeWallet {
        fn drop(&mut self) {
            self.hardware.log("close", &self.host_path);
        }
    }

    /// What a locked Nano Gen5 answers the device read with.
    fn locked_error() -> SignerError {
        map_rw_err(RemoteWalletError::Protocol("Unknown error"))
    }

    fn fake_key(host_path: &str) -> (crate::sdk_adapter::Keypair, Pubkey) {
        device_key(host_path.bytes().fold(0, u8::wrapping_add))
    }

    impl FakeHardware {
        fn bench(&self) -> std::sync::MutexGuard<'_, Bench> {
            self.0.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn log(&self, call: &str, host_path: &str) {
            self.bench().calls.push(format!("{call} {host_path}"));
        }

        /// Log `call`, and fail it if its device is faulty.
        fn call(&self, call: &str, host_path: &str) -> Result<(), SignerError> {
            self.log(call, host_path);
            let mut bench = self.bench();
            match bench.faulty.iter().position(|p| p == host_path) {
                Some(i) => {
                    bench.faulty.remove(i);
                    Err(SignerError::NotAvailable("device lost".to_string()))
                }
                None => Ok(()),
            }
        }

        /// [`FakeHardware::call`] on an open device, which the user can decline.
        fn prompt(&self, call: &str, host_path: &str) -> Result<(), SignerError> {
            self.call(call, host_path)?;
            let mut bench = self.bench();
            if !bench.attached.iter().flatten().any(|p| p == host_path) {
                return Err(SignerError::NotAvailable("device lost".to_string()));
            }
            match bench.declined.iter().position(|p| p == host_path) {
                Some(i) => {
                    bench.declined.remove(i);
                    Err(SignerError::UserRejected("declined".to_string()))
                }
                None => Ok(()),
            }
        }

        fn sign(&self, wallet: &FakeWallet, message: &[u8]) -> Result<[u8; 64], SignerError> {
            self.prompt("sign", &wallet.host_path)?;
            let prompt = self.bench().prompt.take();
            if let Some((reached, answer)) = prompt {
                let _ = reached.send(());
                let _ = answer.recv();
            }
            let (key, _) = self.key(&wallet.host_path);
            signature_bytes(crate::sdk_adapter::keypair_sign_message(&key, message))
        }

        fn key(&self, host_path: &str) -> (crate::sdk_adapter::Keypair, Pubkey) {
            let bench = self.bench();
            fake_key(bench.keys.get(host_path).map_or(host_path, String::as_str))
        }
    }

    impl Hardware for FakeHardware {
        type Wallet = FakeWallet;
        type Listing = Vec<Vec<String>>;

        fn list(&self) -> Result<Vec<Vec<String>>, SignerError> {
            let mut bench = self.bench();
            bench.listings += 1;
            if bench.unlisted_after.is_some_and(|n| bench.listings > n) {
                return Err(SignerError::NotAvailable("listing failed".to_string()));
            }
            if bench.attached.is_empty() {
                return Err(self.unenumerated());
            }
            Ok(bench.attached.clone())
        }

        fn resolve(
            &self,
            listing: &Vec<Vec<String>>,
            host_device_path: Option<&str>,
        ) -> Result<Vec<String>, SignerError> {
            let mut bench = self.bench();
            bench.calls.push(match host_device_path {
                Some(want) => format!("resolve {want}"),
                None => "resolve".to_string(),
            });
            let serial = bench.serial;
            let candidates: Vec<dashboard::Candidate<'_>> = listing
                .iter()
                .flatten()
                .map(|path| dashboard::Candidate { path, serial })
                .collect();
            match host_device_path {
                Some(want) => device_interfaces(&candidates, want),
                None => sole_interfaces(&candidates),
            }
        }

        fn open(
            &self,
            listing: &Vec<Vec<String>>,
            host_path: &str,
        ) -> Result<Option<(String, FakeWallet)>, SignerError> {
            self.call("open", host_path)?;
            let bench = self.bench();
            if bench.vanished.iter().any(|p| p == host_path) {
                return Ok(None);
            }
            if bench.locked.iter().any(|p| p == host_path) {
                return Err(locked_error());
            }
            if bench.held_elsewhere.iter().any(|p| p == host_path) {
                return Err(unopenable_error());
            }
            let listed: Vec<&str> = listing.iter().flatten().map(String::as_str).collect();
            let Some(host_path) =
                dashboard::select_ledger(&listed, host_path).map(|i| listed[i].to_string())
            else {
                return Ok(None);
            };
            drop(bench);
            Ok(Some((
                host_path.clone(),
                FakeWallet {
                    host_path,
                    hardware: self.clone(),
                },
            )))
        }

        fn unenumerated(&self) -> SignerError {
            SignerError::NotAvailable(unenumerated_detail(&[0x0008], RESOLVED_REMOTE_WALLET))
        }

        fn launch_app(&self, _: Option<&str>) -> Result<bool, SignerError> {
            let mut bench = self.bench();
            bench.calls.push("launch".to_string());
            if let Some(host_path) = bench.relaunched_at.take() {
                bench.attached = vec![vec![host_path]];
            }
            Ok(!bench.app_running)
        }

        fn pubkey(
            &self,
            wallet: &FakeWallet,
            _: &DerivationPath,
            confirm: bool,
        ) -> Result<[u8; 32], SignerError> {
            let call = if confirm { "confirm" } else { "pubkey" };
            self.prompt(call, &wallet.host_path)?;
            Ok(self.key(&wallet.host_path).1.to_bytes())
        }

        fn sign_transaction(
            &self,
            wallet: &FakeWallet,
            _: &DerivationPath,
            message: &[u8],
        ) -> Result<[u8; 64], SignerError> {
            self.sign(wallet, message)
        }

        fn sign_offchain(
            &self,
            wallet: &FakeWallet,
            _: &DerivationPath,
            message: &[u8],
        ) -> Result<[u8; 64], SignerError> {
            self.sign(wallet, message)
        }

        fn is_attached(&self) -> bool {
            !self.bench().attached.is_empty()
        }

        fn settle(&self) {}
    }

    /// The real [`device_thread`] over fake Ledgers, reached the way a signer
    /// reaches it.
    struct Rig {
        _guard: std::sync::MutexGuard<'static, ()>,
        hardware: FakeHardware,
        tx: Sender<DeviceCommand>,
    }

    impl Rig {
        fn attach(host_paths: &[&str]) -> Self {
            let guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            DEVICE_BUSY.store(false, Ordering::SeqCst);
            let hardware = FakeHardware(Arc::default());
            hardware.bench().attached = host_paths.iter().map(|p| vec![p.to_string()]).collect();
            let (tx, rx) = mpsc::channel();
            let on_thread = hardware.clone();
            std::thread::spawn(move || device_thread(on_thread, rx));
            *CHANNEL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());
            Self {
                _guard: guard,
                hardware,
                tx,
            }
        }

        /// The hardware calls since the last look, once the thread has served
        /// everything sent before.
        fn calls(&self) -> Vec<String> {
            assert!(idle(), "the device thread kept its claim");
            let (reply, answered) = mpsc::channel();
            self.tx
                .send(DeviceCommand::IsAttached { reply })
                .expect("the device thread runs");
            answered.recv().expect("the device thread answers");
            std::mem::take(&mut self.hardware.bench().calls)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            *CHANNEL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = None;
            idle();
        }
    }

    /// Wait for the device thread to drop the last command and its claim,
    /// which it does after replying.
    fn idle() -> bool {
        (0..1000).any(|_| {
            let free = DeviceClaim::try_acquire().is_some();
            if !free {
                std::thread::sleep(Duration::from_millis(1));
            }
            free
        })
    }

    /// A connect that reaches no user.
    fn quiet(host_device_path: Option<&str>) -> LedgerConfig {
        LedgerConfig {
            host_device_path: host_device_path.map(str::to_string),
            signing_timeout: Duration::from_secs(5),
            auto_open_app: false,
            ..LedgerConfig::default()
        }
    }

    fn connect(config: LedgerConfig) -> LedgerSigner {
        assert!(idle(), "the device thread kept its claim");
        LedgerSigner::connect_with(config).expect("the fake device connects")
    }

    fn assert_refuses_two(connected: Result<LedgerSigner, SignerError>) {
        let Err(err) = connected else {
            panic!("connected with two Ledgers attached");
        };
        assert_eq!(
            err.detail_string(),
            multiple_devices_error(2).detail_string()
        );
    }

    async fn sign(signer: &LedgerSigner) -> Result<Signature, SignerError> {
        assert!(idle(), "the device thread kept its claim");
        signer.sign_message(b"pay 1 SOL").await
    }

    #[tokio::test]
    async fn release_closes_only_its_device() {
        let rig = Rig::attach(&["/a", "/b"]);
        let a = connect(quiet(Some("/a")));
        let b = connect(quiet(Some("/b")));
        rig.calls();
        drop(a);
        assert_eq!(rig.calls(), ["close /a"]);
        sign(&b).await.expect("its session is kept");
        assert_eq!(rig.calls(), ["sign /b"]);
    }

    #[tokio::test]
    async fn release_keeps_a_shared_session() {
        let rig = Rig::attach(&["/a"]);
        let unnamed = connect(quiet(None));
        let named = connect(quiet(Some("/a")));
        rig.calls();
        drop(unnamed);
        assert!(rig.calls().is_empty(), "a named signer still uses /a");

        let unnamed = connect(quiet(None));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&named).await.expect_err("the device was lost");
        sign(&named).await.expect("reopened");
        drop(named);
        sign(&unnamed).await.expect("still bound");
        assert_eq!(
            rig.calls(),
            [
                "resolve",
                "pubkey /a",
                "sign /a",
                "close /a",
                "resolve /a",
                "open /a",
                "pubkey /a",
                "sign /a",
                "pubkey /a",
                "sign /a"
            ]
        );
        drop(unnamed);
        assert_eq!(rig.calls(), ["close /a"]);
    }

    #[tokio::test]
    async fn alternating_devices_open_each_once() {
        let rig = Rig::attach(&["/a", "/b"]);
        let a = connect(quiet(Some("/a")));
        let b = connect(quiet(Some("/b")));
        for signer in [&a, &b, &a, &b] {
            sign(signer).await.expect("signs");
        }
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "pubkey /a",
                "resolve /b",
                "open /b",
                "pubkey /b",
                "sign /a",
                "sign /b",
                "sign /a",
                "sign /b"
            ]
        );
    }

    #[tokio::test]
    async fn a_fault_reopens_only_its_device() {
        let rig = Rig::attach(&["/a", "/b"]);
        let a = connect(quiet(Some("/a")));
        let b = connect(quiet(Some("/b")));
        rig.calls();
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&a).await.expect_err("the device was lost");
        sign(&b).await.expect("its session is untouched");
        sign(&a).await.expect("reopened");
        assert_eq!(
            rig.calls(),
            [
                "sign /a",
                "close /a",
                "sign /b",
                "resolve /a",
                "open /a",
                "pubkey /a",
                "sign /a"
            ]
        );
    }

    #[tokio::test]
    async fn a_reopen_lists_once() {
        let rig = Rig::attach(&["/a"]);
        let a = connect(quiet(Some("/a")));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&a).await.expect_err("the device was lost");
        rig.calls();
        rig.hardware.bench().listings = 0;
        sign(&a).await.expect("reopened");
        assert_eq!(
            rig.calls(),
            ["resolve /a", "open /a", "pubkey /a", "sign /a"]
        );
        assert_eq!(rig.hardware.bench().listings, 1);
    }

    #[tokio::test]
    async fn an_unnamed_signer_shares_a_named_session() {
        let rig = Rig::attach(&["/a"]);
        let named = connect(quiet(Some("/a")));
        let unnamed = connect(quiet(None));
        sign(&unnamed).await.expect("signs");
        drop(named);
        sign(&unnamed).await.expect("still bound");
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "pubkey /a",
                "resolve",
                "pubkey /a",
                "sign /a",
                "sign /a"
            ]
        );
        drop(unnamed);
        assert_eq!(rig.calls(), ["close /a"]);
    }

    #[test]
    fn connect_rebuilds_a_stale_session() {
        let rig = Rig::attach(&["/a"]);
        let _first = connect(quiet(Some("/a")));
        rig.hardware.bench().faulty.push("/a".to_string());
        let _second = connect(quiet(Some("/a")));
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "pubkey /a",
                "pubkey /a",
                "close /a",
                "open /a",
                "pubkey /a"
            ]
        );
    }

    #[test]
    fn confirm_reopens() {
        let rig = Rig::attach(&["/a"]);
        let _held = connect(quiet(Some("/a")));
        let _confirmed = connect(LedgerConfig {
            confirm_pubkey_on_device: true,
            ..quiet(Some("/a"))
        });
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "pubkey /a",
                "resolve /a",
                "close /a",
                "open /a",
                "confirm /a"
            ]
        );
    }

    #[test]
    fn connect_follows_a_relaunched_device() {
        let rig = Rig::attach(&["/dashboard"]);
        {
            let mut bench = rig.hardware.bench();
            bench.faulty.push("/dashboard".to_string());
            bench.relaunched_at = Some("/solana".to_string());
        }
        let signer = connect(LedgerConfig {
            auto_open_app: true,
            ..quiet(None)
        });
        assert_eq!(signer.pubkey(), fake_key("/solana").1);
        assert_eq!(
            rig.calls(),
            [
                "resolve",
                "open /dashboard",
                "launch",
                "resolve",
                "open /solana",
                "pubkey /solana"
            ]
        );
    }

    #[test]
    fn a_named_signer_follows_its_relaunched_device() {
        let at = |interface: u8| {
            format!("IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@{interface}")
        };
        let (dashboard, solana) = (at(0), at(1));
        let rig = Rig::attach(&[&dashboard]);
        {
            let mut bench = rig.hardware.bench();
            bench.faulty.push(dashboard.clone());
            bench.relaunched_at = Some(solana.clone());
        }
        let signer = connect(LedgerConfig {
            auto_open_app: true,
            ..quiet(Some(&dashboard))
        });
        assert_eq!(signer.pubkey(), fake_key(&solana).1);
        assert_eq!(
            rig.calls(),
            [
                format!("resolve {dashboard}"),
                format!("open {dashboard}"),
                "launch".to_string(),
                format!("resolve {dashboard}"),
                format!("open {solana}"),
                format!("pubkey {solana}")
            ]
        );
    }

    #[test]
    fn a_declined_confirm_is_not_retried() {
        let rig = Rig::attach(&["/a"]);
        let _held = connect(quiet(Some("/a")));
        rig.calls();
        rig.hardware.bench().declined.push("/a".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(LedgerConfig {
            confirm_pubkey_on_device: true,
            auto_open_app: true,
            ..quiet(Some("/a"))
        })
        .expect_err("declined");
        assert!(matches!(err, SignerError::UserRejected(_)), "got: {err:?}");
        assert_eq!(
            rig.calls(),
            ["resolve /a", "close /a", "open /a", "confirm /a"]
        );
    }

    #[test]
    fn a_running_app_is_not_waited_for() {
        let rig = Rig::attach(&["/a"]);
        {
            let mut bench = rig.hardware.bench();
            bench.faulty.push("/a".to_string());
            bench.app_running = true;
        }
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(LedgerConfig {
            auto_open_app: true,
            ..quiet(Some("/a"))
        })
        .expect_err("the device was lost");
        assert!(
            matches!(&err, SignerError::NotAvailable(d) if d == "device lost"),
            "got: {err:?}"
        );
        assert_eq!(rig.calls(), ["resolve /a", "open /a", "launch"]);
    }

    #[test]
    fn an_unnamed_confirm_refuses_two_devices() {
        let rig = Rig::attach(&["/a"]);
        let _unnamed = connect(quiet(None));
        rig.calls();
        rig.hardware.bench().attached.push(vec!["/b".to_string()]);
        assert!(idle(), "the device thread kept its claim");
        assert_refuses_two(LedgerSigner::connect(None, true, None));
        assert_eq!(rig.calls(), ["resolve"]);
    }

    #[test]
    fn an_unnamed_connect_refuses_two_devices() {
        let rig = Rig::attach(&["/a"]);
        let _unnamed = connect(quiet(None));
        rig.calls();
        rig.hardware.bench().attached.push(vec!["/b".to_string()]);
        assert!(idle(), "the device thread kept its claim");
        assert_refuses_two(LedgerSigner::connect_with(quiet(None)));
        assert_eq!(rig.calls(), ["resolve"]);
    }

    #[test]
    fn a_confirm_relists_devices() {
        let rig = Rig::attach(&["/a"]);
        let _unnamed = connect(quiet(None));
        rig.calls();
        let _confirmed = connect(LedgerConfig {
            confirm_pubkey_on_device: true,
            ..quiet(None)
        });
        assert_eq!(
            rig.calls(),
            ["resolve", "close /a", "open /a", "confirm /a"]
        );
    }

    #[test]
    fn resolve_skips_a_sibling_that_does_not_open() {
        let rig = Rig::attach(&[]);
        {
            let mut bench = rig.hardware.bench();
            bench.attached = vec![vec!["/usb/a@0".to_string(), "/usb/a@1".to_string()]];
            bench.faulty.push("/usb/a@0".to_string());
        }
        let signer = connect(quiet(None));
        assert_eq!(signer.pubkey(), fake_key("/usb/a@1").1);
        assert_eq!(
            rig.calls(),
            [
                "resolve",
                "open /usb/a@0",
                "open /usb/a@1",
                "pubkey /usb/a@1"
            ]
        );
    }

    #[test]
    fn a_locked_sole_device_says_so() {
        let rig = Rig::attach(&["/a"]);
        rig.hardware.bench().locked.push("/a".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(None)).expect_err("locked");
        assert_eq!(err.detail_string(), locked_error().detail_string());
    }

    #[test]
    fn a_locked_named_device_says_so() {
        let rig = Rig::attach(&["/a"]);
        rig.hardware.bench().locked.push("/a".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(Some("/a"))).expect_err("locked");
        assert_eq!(err.detail_string(), locked_error().detail_string());
    }

    #[test]
    fn a_locked_interface_outranks_a_failed_one() {
        let rig = attach_two_interfaces();
        {
            let mut bench = rig.hardware.bench();
            bench.locked.push("/usb/a@0".to_string());
            bench.faulty.push("/usb/a@1".to_string());
        }
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(None)).expect_err("locked");
        assert_eq!(err.detail_string(), locked_error().detail_string());
        assert_eq!(rig.calls(), ["resolve", "open /usb/a@0", "open /usb/a@1"]);
    }

    #[test]
    fn a_named_signer_opens_only_its_path() {
        let rig = attach_two_interfaces();
        rig.hardware.bench().locked.push("/usb/a@0".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(Some("/usb/a@0"))).expect_err("locked");
        assert_eq!(err.detail_string(), locked_error().detail_string());
        assert_eq!(rig.calls(), ["resolve /usb/a@0", "open /usb/a@0"]);
    }

    #[test]
    fn a_vanished_sibling_names_only_the_callers_path() {
        let rig = Rig::attach(&["/usb/a@1"]);
        rig.hardware.bench().vanished.push("/usb/a@1".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(Some("/usb/a@0"))).expect_err("unplugged");
        assert_eq!(
            err.detail_string(),
            no_device_at("/usb/a@0").detail_string()
        );
        assert_eq!(rig.calls(), ["resolve /usb/a@0", "open /usb/a@1"]);
    }

    #[test]
    fn a_vanished_sole_device_names_no_path() {
        let rig = Rig::attach(&["/a"]);
        rig.hardware.bench().vanished.push("/a".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(None)).expect_err("unplugged");
        assert_eq!(
            err.detail_string(),
            rig.hardware.unenumerated().detail_string()
        );
    }

    #[tokio::test]
    async fn a_failed_command_resolves_again() {
        let rig = Rig::attach(&["/a"]);
        let unnamed = connect(quiet(None));
        rig.calls();
        rig.hardware.bench().declined.push("/a".to_string());
        sign(&unnamed).await.expect_err("declined");
        sign(&unnamed).await.expect("signs");
        assert_eq!(rig.calls(), ["sign /a", "sign /a"]);
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&unnamed).await.expect_err("the device was lost");
        sign(&unnamed).await.expect("signs");
        assert_eq!(
            rig.calls(),
            [
                "sign /a",
                "close /a",
                "resolve",
                "open /a",
                "pubkey /a",
                "sign /a"
            ]
        );
    }

    #[tokio::test]
    async fn a_moved_device_leaves_its_old_path() {
        let rig = Rig::attach(&["/a"]);
        let unnamed = connect(quiet(None));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&unnamed).await.expect_err("the device was lost");
        {
            let mut bench = rig.hardware.bench();
            bench.attached = vec![vec!["/b".to_string()]];
            bench.keys.insert("/b".to_string(), "/a".to_string());
        }
        assert!(idle(), "the device thread kept its claim");
        assert!(unnamed.is_available().await, "reachable at its new path");
        rig.hardware.bench().attached.push(vec!["/a".to_string()]);
        let named = connect(quiet(Some("/a")));
        rig.calls();
        drop(named);
        assert_eq!(rig.calls(), ["close /a"], "the unnamed signer left /a");
    }

    #[tokio::test]
    async fn an_unnamed_signer_keeps_its_device() {
        let rig = Rig::attach(&["/a"]);
        let a = connect(quiet(None));
        rig.hardware.bench().attached = vec![vec!["/b".to_string()]];
        let _b = connect(quiet(None));
        rig.hardware.bench().attached.push(vec!["/a".to_string()]);
        rig.calls();
        sign(&a).await.expect("signs on A");
        assert_eq!(rig.calls(), ["sign /a"]);
    }

    #[tokio::test]
    async fn an_unnamed_signer_refuses_another_device() {
        let rig = Rig::attach(&["/a"]);
        let a = connect(quiet(None));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&a).await.expect_err("the device was lost");
        rig.hardware.bench().attached = vec![vec!["/b".to_string()]];
        let _b = connect(quiet(None));
        rig.hardware.bench().attached.push(vec!["/a".to_string()]);
        rig.calls();
        let err = sign(&a).await.expect_err("two Ledgers attached");
        assert_eq!(
            err.detail_string(),
            multiple_devices_error(2).detail_string()
        );
        assert_eq!(rig.calls(), ["resolve"]);
    }

    #[tokio::test]
    async fn unnamed_signers_share_a_session() {
        let rig = Rig::attach(&["/a"]);
        let first = connect(quiet(None));
        let second = connect(quiet(None));
        sign(&first).await.expect("signs");
        sign(&second).await.expect("signs");
        assert_eq!(
            rig.calls(),
            [
                "resolve",
                "open /a",
                "pubkey /a",
                "resolve",
                "pubkey /a",
                "sign /a",
                "sign /a"
            ]
        );
    }

    fn attach_two_interfaces() -> Rig {
        let rig = Rig::attach(&[]);
        rig.hardware.bench().attached = vec![vec!["/usb/a@0".to_string(), "/usb/a@1".to_string()]];
        rig
    }

    #[tokio::test]
    async fn a_named_signer_skips_a_sibling_session() {
        let rig = attach_two_interfaces();
        let _first = connect(quiet(Some("/usb/a@0")));
        let second = connect(quiet(Some("/usb/a@1")));
        sign(&second).await.expect("signs");
        assert_eq!(
            rig.calls(),
            [
                "resolve /usb/a@0",
                "open /usb/a@0",
                "pubkey /usb/a@0",
                "resolve /usb/a@1",
                "open /usb/a@1",
                "pubkey /usb/a@1",
                "sign /usb/a@1"
            ]
        );
    }

    #[test]
    fn a_sibling_session_closes_before_launch() {
        let rig = attach_two_interfaces();
        let _held = connect(quiet(Some("/usb/a@1")));
        rig.calls();
        {
            let mut bench = rig.hardware.bench();
            bench.faulty.push("/usb/a@0".to_string());
            bench.app_running = true;
        }
        assert!(idle(), "the device thread kept its claim");
        LedgerSigner::connect_with(LedgerConfig {
            auto_open_app: true,
            ..quiet(Some("/usb/a@0"))
        })
        .expect_err("the device was lost");
        assert_eq!(
            rig.calls(),
            [
                "resolve /usb/a@0",
                "open /usb/a@0",
                "close /usb/a@1",
                "launch"
            ]
        );
    }

    #[tokio::test]
    async fn a_swapped_device_is_not_available() {
        let rig = Rig::attach(&["/a"]);
        let signer = connect(quiet(Some("/a")));
        assert!(idle(), "the device thread kept its claim");
        assert!(signer.is_available().await);
        rig.hardware
            .bench()
            .keys
            .insert("/a".to_string(), "/b".to_string());
        assert!(idle(), "the device thread kept its claim");
        assert!(!signer.is_available().await, "another Ledger answers at /a");
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "pubkey /a",
                "pubkey /a",
                "pubkey /a"
            ]
        );
    }

    #[tokio::test]
    async fn a_swapped_device_reopened_by_another_signer_is_refused() {
        let rig = Rig::attach(&["/a"]);
        let a = connect(quiet(Some("/a")));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&a).await.expect_err("the device was lost");
        rig.hardware
            .bench()
            .keys
            .insert("/a".to_string(), "/b".to_string());
        let _other = connect(quiet(Some("/a")));
        rig.calls();
        let err = sign(&a).await.expect_err("another Ledger answers at /a");
        assert_eq!(err.detail_string(), another_device_error().detail_string());
        assert_eq!(rig.calls(), ["pubkey /a"]);
    }

    #[tokio::test]
    async fn a_first_probe_reads_the_key_once() {
        let rig = Rig::attach(&["/a"]);
        let a = connect(quiet(Some("/a")));
        rig.hardware.bench().faulty.push("/a".to_string());
        sign(&a).await.expect_err("the device was lost");
        let _other = connect(quiet(Some("/a")));
        rig.calls();
        assert!(a.is_available().await);
        assert_eq!(rig.calls(), ["pubkey /a"]);
    }

    /// Device A sits at its prompt inside the device thread while B's signer
    /// asks for B, whose session is open and idle.
    #[tokio::test]
    async fn a_busy_device_refuses_another() {
        let rig = Rig::attach(&["/a", "/b"]);
        let a = connect(quiet(Some("/a")));
        let b = connect(quiet(Some("/b")));
        rig.calls();
        let (reached, at_prompt) = mpsc::channel();
        let (answer, awaiting) = mpsc::channel();
        rig.hardware.bench().prompt = Some((reached, awaiting));

        let b = &b;
        let (signed, (refused, waited)) = tokio::join!(sign(&a), async move {
            tokio::task::spawn_blocking(move || at_prompt.recv())
                .await
                .expect("the wait runs")
                .expect("A reaches its prompt");
            let started = Instant::now();
            let refused = b.sign_message(b"pay 1 SOL").await;
            let waited = started.elapsed();
            let _ = answer.send(());
            (refused, waited)
        });

        signed.expect("A signs once answered");
        let err = refused.expect_err("B must not queue behind A's prompt");
        assert!(
            matches!(&err, SignerError::NotAvailable(d) if d == BUSY_DETAIL),
            "got: {err:?}"
        );
        assert!(waited < Duration::from_secs(1), "refused after {waited:?}");
        assert_eq!(rig.calls(), ["sign /a"]);
    }

    /// Signers named for each of two devices and two unnamed ones, through
    /// seeded random connects, signs, unplugs, replugs and drops, over two
    /// plain paths and over two Nano Gen5s that report one serial. A signer's
    /// command prompts only the device holding its key, or the one its connect
    /// was meant to reach, or is refused: as multiple devices only when
    /// unnamed, as not found only while that device is unplugged.
    #[tokio::test]
    async fn a_random_walk_prompts_only_its_device() {
        let gen5 = |location: &str| {
            format!("IOService:/AppleT8103/usb-drd0/ledger@{location}/IOUSBHostInterface@0")
        };
        let (gen5_a, gen5_b) = (gen5("01100000"), gen5("01200000"));
        for (devices, serial) in [
            (["/a", "/b"], None),
            ([gen5_a.as_str(), gen5_b.as_str()], Some("0001")),
        ] {
            for seed in 1u64..=8 {
                let rig = Rig::attach(&devices);
                rig.hardware.bench().serial = serial;
                let attached =
                    |path: &str| rig.hardware.bench().attached.iter().any(|d| d[0] == path);
                let multiple = multiple_devices_error(2).detail_string();
                let not_found = [
                    rig.hardware.unenumerated(),
                    no_device_at(devices[0]),
                    no_device_at(devices[1]),
                    another_device_error(),
                    SignerError::NotAvailable("device lost".to_string()),
                ]
                .map(|error| error.detail_string());
                let named = [Some(devices[0]), Some(devices[1]), None, None];
                let mut signers: [Option<LedgerSigner>; 4] = Default::default();
                let mut state = seed;
                let mut pick = |n: u64| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state % n) as usize
                };
                let mut steps = Vec::new();
                for _ in 0..500 {
                    let (op, slot, device) = (pick(6), pick(4), devices[pick(2)]);
                    let mut key = None;
                    let mut own = named[slot];
                    let mut refused = None;
                    match op {
                        0 | 1 => {
                            steps.push(format!("connect slot {slot}, confirm: {}", op == 1));
                            let present: Vec<&str> =
                                devices.into_iter().filter(|p| attached(p)).collect();
                            let meant = match named[slot] {
                                Some(path) => present.contains(&path).then_some(path),
                                None => match present.as_slice() {
                                    [sole] => Some(*sole),
                                    _ => None,
                                },
                            };
                            key = meant.map(|path| fake_key(path).1);
                            assert!(idle(), "the device thread kept its claim");
                            match LedgerSigner::connect_with(LedgerConfig {
                                confirm_pubkey_on_device: op == 1,
                                ..quiet(named[slot])
                            }) {
                                Ok(signer) => signers[slot] = Some(signer),
                                Err(error) => refused = Some(error),
                            }
                        }
                        2 => {
                            steps.push(format!("sign slot {slot}"));
                            if let Some(signer) = &signers[slot] {
                                key = Some(signer.pubkey());
                                own = devices
                                    .into_iter()
                                    .find(|p| fake_key(p).1 == signer.pubkey());
                                refused = sign(signer).await.err();
                            }
                        }
                        3 => {
                            steps.push(format!("unplug {device}"));
                            rig.hardware.bench().attached.retain(|d| d[0] != device);
                        }
                        4 => {
                            steps.push(format!("replug {device}"));
                            if !attached(device) {
                                rig.hardware.bench().attached.push(vec![device.to_string()]);
                            }
                        }
                        _ => {
                            steps.push(format!("drop slot {slot}"));
                            signers[slot] = None;
                        }
                    }
                    let calls = rig.calls();
                    let replay = format!(
                        "seed {seed}, serial {serial:?}, steps:\n{}",
                        steps.join("\n")
                    );
                    for call in &calls {
                        let Some(prompted) = call
                            .strip_prefix("sign ")
                            .or_else(|| call.strip_prefix("confirm "))
                        else {
                            continue;
                        };
                        assert_eq!(
                            key,
                            Some(fake_key(prompted).1),
                            "`{call}` prompted another device; {replay}"
                        );
                    }
                    if let Some(error) = refused.map(|error| error.detail_string()) {
                        let unplugged = own.is_none_or(|own| !attached(own));
                        assert!(
                            (named[slot].is_none() && error == multiple)
                                || (unplugged && not_found.contains(&error)),
                            "refused with {error}; {replay}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn sibling_interfaces_resolve_to_one_device() {
        let first = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0";
        let second = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1";
        for serial in [Some("0001"), None] {
            let candidates = [first, second].map(|path| dashboard::Candidate { path, serial });
            assert_eq!(
                sole_interfaces(&candidates).expect("one device"),
                [first, second]
            );
        }
    }

    #[test]
    fn device_interfaces_lists_the_selected_first() {
        let first = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0";
        let second = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1";
        let other = "IOService:/AppleT8103/usb-drd0/ledger@01200000/IOUSBHostInterface@0";
        let candidates =
            [first, second, other].map(|path| dashboard::Candidate { path, serial: None });
        assert_eq!(
            device_interfaces(&candidates, second).expect("listed"),
            [second, first]
        );
        assert_eq!(
            device_interfaces(&candidates, other).expect("listed"),
            [other]
        );
    }

    #[test]
    fn device_interfaces_refuses_an_unknown_path() {
        let listed = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0";
        let candidates = [dashboard::Candidate {
            path: listed,
            serial: None,
        }];
        let err = device_interfaces(&candidates, "/dev/hidraw9").expect_err("not listed");
        assert_eq!(
            err.detail_string(),
            no_device_at("/dev/hidraw9").detail_string()
        );
    }

    /// Print what is actually attached and what the device says about itself.
    ///
    /// Not an assertion, a diagnostic. When a connect fails, the error cannot
    /// distinguish locked from busy from wrong-app, so this reports the raw
    /// facts: which product ids `hidapi` can see, whether
    /// `solana-remote-wallet` enumerated them, and what the BOLOS dashboard
    /// says is running. Run it with:
    ///
    /// ```bash
    /// just rust-ledger-diagnose
    /// ```
    #[test]
    #[ignore = "diagnostic; needs a device. run via `just rust-ledger-diagnose`"]
    fn diagnose_attached_ledger() {
        eprintln!("\n─── hidapi enumeration ───");
        match hidapi::HidApi::new() {
            Ok(api) => {
                let mut found = 0;
                for d in api.device_list().filter(|d| d.vendor_id() == LEDGER_VID) {
                    found += 1;
                    eprintln!(
                        "  pid=0x{:04x} interface={} usage_page=0x{:04x} product={:?}",
                        d.product_id(),
                        d.interface_number(),
                        d.usage_page(),
                        d.product_string().unwrap_or("<none>")
                    );
                    eprintln!("    path={}", d.path().to_string_lossy());
                    // The primary key `sole_ledger` groups interfaces by. Worth
                    // printing: when it is absent, that grouping falls back to
                    // path adjacency, and whether the fallback works at all
                    // depends on what the platform's paths look like.
                    eprintln!("    serial={:?}", d.serial_number());
                    if GEN5_PIDS.contains(&d.product_id()) {
                        eprintln!("    -> in the Nano Gen5 PID set (needs remote-wallet >= 4.1)");
                    }
                }
                if found == 0 {
                    eprintln!("  no device with vendor id 0x2c97");
                }
            }
            Err(e) => eprintln!("  hidapi unavailable: {e}"),
        }

        eprintln!("\n─── LedgerSigner::is_attached() ───");
        eprintln!("  {}", LedgerSigner::is_attached());

        eprintln!("\n─── BOLOS dashboard: which app is running? ───");
        match dashboard::running_app(None) {
            Ok(Some(app)) => eprintln!("  running app: {app:?}"),
            Ok(None) => eprintln!("  dashboard answered but named no app"),
            Err(e) => eprintln!("  dashboard unreachable: {}", e.detail_string()),
        }

        // The raw `RemoteWalletError`, not our mapped one. `map_rw_err` folds
        // every `Protocol(_)` into one locked/busy message, and there are three
        // distinct strings behind it -- "Unknown error", "Version packet size
        // mismatch" and "Key packet size mismatch" -- which mean entirely
        // different things. Diagnosing needs the original.
        // What `solana-remote-wallet` chokes on. It requires the app-config
        // payload to be exactly 5 bytes (current) or 4 (deprecated) and reports
        // anything else as an opaque "Version packet size mismatch" with the
        // bytes discarded. Ask the app directly.
        eprintln!("\n─── BOLOS getAppAndVersion (raw) ───");
        match dashboard::probe_apdu(None, 0xb0, 0x01, 0, 0, &[]) {
            Ok((payload, sw)) => {
                eprintln!("  status=0x{sw:04x} bytes={:02x?}", payload);
                // format: 01 | name_len | name | version_len | version | ...
                if payload.len() > 2 {
                    let n = payload[1] as usize;
                    let name = String::from_utf8_lossy(&payload[2..2 + n]);
                    let vl = payload[2 + n] as usize;
                    let ver = String::from_utf8_lossy(&payload[3 + n..3 + n + vl]);
                    eprintln!("  app={name:?} version={ver:?}");
                }
            }
            Err(e) => eprintln!("  {}", e.detail_string()),
        }

        eprintln!("\n─── Solana app configuration (CLA 0xe0) ───");
        for (name, ins) in [
            ("GET_APP_CONFIGURATION 0x04", 0x04u8),
            ("DEPRECATED 0x01", 0x01u8),
        ] {
            match dashboard::probe_apdu(None, 0xe0, ins, 0, 0, &[]) {
                Ok((payload, sw)) => eprintln!(
                    "  {name}: status=0x{sw:04x} len={} bytes={:02x?}",
                    payload.len(),
                    payload
                ),
                Err(e) => eprintln!("  {name}: {}", e.detail_string()),
            }
        }

        eprintln!("\n─── solana-remote-wallet, raw errors ───");
        use solana_remote_wallet::remote_wallet::{initialize_wallet_manager, RemoteWalletType};
        match initialize_wallet_manager() {
            Err(e) => eprintln!("  initialize_wallet_manager: {e:?}"),
            Ok(manager) => {
                match manager.update_devices() {
                    Ok(n) => eprintln!("  update_devices: {n} device(s)"),
                    Err(e) => eprintln!("  update_devices: {e:?}"),
                }
                let ledgers: Vec<_> = manager
                    .list_devices()
                    .into_iter()
                    .filter_map(|d| match d.wallet_type {
                        RemoteWalletType::Ledger(w) => Some(w),
                        _ => None,
                    })
                    .collect();
                eprintln!("  list_devices: {} ledger(s)", ledgers.len());
                for wallet in ledgers {
                    eprintln!("    pretty_path={}", wallet.pretty_path);
                    let path = DerivationPath::from_absolute_path_str(DEFAULT_DERIVATION_PATH)
                        .expect("default path parses");
                    match wallet.get_pubkey(&path, false) {
                        Ok(pk) => eprintln!("    get_pubkey -> {pk}"),
                        Err(e) => eprintln!("    get_pubkey -> RAW {e:?}"),
                    }
                }
            }
        }
        eprintln!();
    }

    #[test]
    fn the_enumeration_guard_reports_the_version_it_resolved() {
        // The version claim must rest on the version actually resolved: a
        // 4.2.2 build with a held device is not a dependency problem.
        let gen5 = [0x8000u16];

        // Resolved 4.0.x: the version really is the cause, and saying so is
        // now a checked claim rather than an assumed one.
        let old = unenumerated_detail(&gen5, "4.0.3");
        assert!(old.contains("4.0.3"), "must report what it resolved: {old}");
        assert!(
            old.contains("predates the Gen5 product ids"),
            "the one case where the version is the answer: {old}"
        );

        // Resolved 4.2.2: the version is not the cause and must not be blamed.
        let current = unenumerated_detail(&gen5, "4.2.2");
        assert!(
            current.contains("4.2.2"),
            "must report what it resolved: {current}"
        );
        assert!(
            current.contains("not the cause"),
            "must clear the version rather than blame it: {current}"
        );
        assert!(
            !current.contains("predates"),
            "must not claim the 4.0.x diagnosis on a 4.2.x build: {current}"
        );
        // Both remaining causes, neither ranked above the other.
        assert!(
            current.contains("agave/pull/15100"),
            "must name the app-config incompatibility: {current}"
        );
        assert!(
            current.contains("holding the device"),
            "must name the contention cause: {current}"
        );

        // And the way to tell them apart, which is the actionable part.
        for m in [&old, &current] {
            assert!(
                m.contains("rust-ledger-diagnose") && m.contains("raw HID open"),
                "must say how to separate the causes: {m}"
            );
        }
    }

    #[test]
    fn an_unknown_resolved_version_rules_nothing_in_or_out() {
        // Unknown version must not assert "not the cause"; must not claim unread facts.
        for unknowable in ["unknown", "not-in-graph", "", "4", "four.two.two"] {
            let detail = unenumerated_detail(&[0x8000], unknowable);
            assert!(
                !detail.contains("not the cause"),
                "must not exonerate an unread version ({unknowable}): {detail}"
            );
            assert!(
                !detail.contains("does carry the Gen5 product ids"),
                "must not assert a capability it did not read ({unknowable}): {detail}"
            );
            assert!(
                !detail.contains("predates"),
                "nor blame one it did not read ({unknowable}): {detail}"
            );
            assert!(
                detail.contains("could not be determined")
                    && detail.contains("cannot be ruled out"),
                "must say it does not know ({unknowable}): {detail}"
            );
            assert!(
                detail.contains("rust-which-remote-wallet"),
                "must say how to find out ({unknowable}): {detail}"
            );
            // Both possibilities still offered, including the one the buggy
            // version silently dropped.
            assert!(
                detail.contains("4.0.x it cannot see this device"),
                "must keep the version cause on the table ({unknowable}): {detail}"
            );
            assert!(detail.contains("agave/pull/15100") && detail.contains("holding the device"));
        }
    }

    #[test]
    fn the_version_classifier_only_answers_when_it_knows() {
        assert_eq!(gen5_support("4.0.3"), Gen5Support::Absent);
        assert_eq!(gen5_support("4.0.0"), Gen5Support::Absent);
        assert_eq!(gen5_support("3.1.14"), Gen5Support::Absent);
        assert_eq!(gen5_support("4.1.0"), Gen5Support::Present);
        assert_eq!(gen5_support("4.2.2"), Gen5Support::Present);
        assert_eq!(
            gen5_support("4.10.0"),
            Gen5Support::Present,
            "10 > 1, not \"1.0\""
        );
        assert_eq!(gen5_support("5.0.0"), Gen5Support::Present);
        for bad in ["unknown", "not-in-graph", "", "4", "4.x", "four.two"] {
            assert_eq!(gen5_support(bad), Gen5Support::Unknown, "{bad}");
        }
    }

    #[test]
    fn a_known_4_1_version_is_the_only_thing_that_rules_the_version_out() {
        // The claim "the crate version is not the cause" is a claim, and only a
        // version that was actually read and is 4.1+ earns it.
        for known_good in ["4.1.0", "4.2.2", "5.0.0"] {
            let detail = unenumerated_detail(&[0x8000], known_good);
            assert!(
                detail.contains("not the cause") && detail.contains(known_good),
                "got: {detail}"
            );
        }
    }

    #[test]
    fn a_non_gen5_product_id_is_not_given_the_gen5_diagnosis() {
        let detail = unenumerated_detail(&[0x0001], "4.2.2");
        assert!(
            detail.contains("does not recognise that product id"),
            "got: {detail}"
        );
        assert!(!detail.contains("Nano Gen5"), "got: {detail}");
    }

    #[test]
    fn the_resolved_version_is_baked_in_by_the_build_script() {
        // If this ever reads `unknown` in this repo, the lockfile walk in
        // build.rs has broken and every message above silently stops naming a
        // version.
        assert_ne!(RESOLVED_REMOTE_WALLET, "unknown");
        assert_ne!(RESOLVED_REMOTE_WALLET, "not-in-graph");
        assert_eq!(
            gen5_support(RESOLVED_REMOTE_WALLET),
            Gen5Support::Present,
            "build.rs should have read a 4.1+ version out of rust/Cargo.lock, got {RESOLVED_REMOTE_WALLET}"
        );
    }

    #[test]
    fn gen5_pids_are_reported_with_the_version_requirement() {
        // A build whose solana-remote-wallet predates 4.1 never enumerates a
        // Gen5, so every layer above says "no Ledger found" while one is
        // plugged in and unlocked. Verified empirically against the two
        // versions in this workspace's registry: 4.0.3 defines PID lists for
        // Nano S / X / S Plus / Stax / Flex only; 4.2.2 adds
        // LEDGER_NANO_GEN5_PIDS. The message has to name that, or the user goes
        // looking at cables.
        assert!(
            GEN5_PIDS.contains(&0x8000),
            "0x8000 is the Gen5 PID we tested against"
        );
        assert!(GEN5_PIDS.contains(&0x0008));
    }

    #[test]
    fn the_two_availability_details_cannot_be_confused() {
        // The hardware suite skips on one of these and fails on the other, and
        // `SignerError` has a single `NotAvailable` variant for both, so the
        // messages are the discriminator. If one ever became a substring of the
        // other, a held device would start reading as an absent one and the
        // suite would go back to reporting success against a device it never
        // spoke to.
        assert!(!BUSY_DETAIL.contains(NO_DEVICE_DETAIL));
        assert!(!NO_DEVICE_DETAIL.contains(BUSY_DETAIL));
        assert!(busy_error().detail_string().contains(BUSY_DETAIL));
        assert!(!busy_error().detail_string().contains(NO_DEVICE_DETAIL));
    }

    #[test]
    fn no_device_error_stays_plain_when_nothing_is_attached() {
        // With no Ledger-vendor device present the message must not speculate
        // about versions. On a machine with a Ledger attached this asserts the
        // enriched form instead, which is the branch that matters.
        // On a thread that never exits: once a thread that called `hidapi`
        // exits, the next `HidApi::new()` aborts on macOS. See [`DEVICE_THREAD`].
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send((no_ledger_enumerated_error(), attached_ledger_pids()));
            loop {
                std::thread::park();
            }
        });
        let (err, attached) = rx.recv().expect("the probe answers");
        assert!(matches!(err, SignerError::NotAvailable(_)));
        let detail = err.detail_string();
        if attached.is_empty() {
            assert!(detail.contains("no Ledger device found"), "got: {detail}");
            assert!(!detail.contains("product id"), "got: {detail}");
        } else {
            assert!(detail.contains("product id"), "got: {detail}");
            assert!(detail.contains("solana-remote-wallet"), "got: {detail}");
        }
    }

    #[test]
    fn default_derivation_path_is_solana_bip44() {
        let path = DerivationPath::from_absolute_path_str(DEFAULT_DERIVATION_PATH);
        assert!(path.is_ok(), "default derivation path must parse");
    }

    #[test]
    fn a_wrong_length_device_signature_is_an_error_not_a_panic() {
        // The length comes from the device; a truncated response must fail
        // the signature, not abort the process.
        let err = signature_bytes([0u8; 63].as_slice()).expect_err("63 bytes is not a signature");
        assert!(matches!(err, SignerError::SigningFailed(_)), "got: {err:?}");
        assert!(signature_bytes([0u8; 65].as_slice()).is_err());
        assert!(signature_bytes([0u8; 64].as_slice()).is_ok());
    }

    #[test]
    fn signature_bytes_roundtrips() {
        // The SDK-selected `Signature` stands in for `solana-remote-wallet`'s:
        // both are `solana-signature` types, and the bridge is byte-level, so
        // this exercises exactly the conversion the device path performs.
        let raw = [7u8; 64];
        let sig = Signature::from(raw);
        assert_eq!(signature_bytes(sig).expect("64 bytes"), raw);
    }

    #[test]
    fn user_cancel_maps_to_user_rejected() {
        let err = map_rw_err(RemoteWalletError::UserCancel);
        assert!(matches!(err, SignerError::UserRejected(_)));
    }

    #[test]
    fn no_device_maps_to_not_available() {
        let err = map_rw_err(RemoteWalletError::NoDeviceFound);
        assert!(matches!(err, SignerError::NotAvailable(_)));
    }

    #[test]
    fn offchain_envelope_matches_the_ledger_app_layout() {
        // Byte-exact against LedgerHQ/app-solana's `parse_offchain_message_header`.
        // Pinning the layout matters more than usual here: the obvious choice —
        // `solana_offchain_message`'s serializer — produces a *different*
        // envelope that the device rejects, so a future refactor "simplifying"
        // this back to the crate would silently break signing again.
        let signer = Pubkey::from([7u8; 32]);
        let payload = b"hello";
        let env = ledger_offchain_envelope(&signer, payload).unwrap();

        assert_eq!(&env[0..16], b"\xffsolana offchain", "signing domain");
        assert_eq!(env[16], 0, "header version");
        assert_eq!(&env[17..49], &[0u8; 32], "application domain: not provided");
        assert_eq!(env[49], 0, "format 0 = RestrictedAscii for printable ASCII");
        assert_eq!(env[50], 1, "exactly one signer");
        assert_eq!(&env[51..83], &[7u8; 32], "the signer's pubkey");
        assert_eq!(&env[83..85], &5u16.to_le_bytes(), "length, little-endian");
        assert_eq!(&env[85..], payload, "message body");
        assert_eq!(env.len(), 85 + payload.len());
    }

    #[test]
    fn offchain_envelope_picks_the_format_from_the_payload() {
        let signer = Pubkey::from([1u8; 32]);
        // Printable ASCII -> RestrictedAscii.
        let ascii = ledger_offchain_envelope(&signer, b"plain text").unwrap();
        assert_eq!(ascii[49], 0);
        // Valid UTF-8 that is not printable ASCII -> LimitedUtf8. The app
        // rejects format 2, so this is the only other value it will take.
        let utf8 = ledger_offchain_envelope(&signer, "café ☕".as_bytes()).unwrap();
        assert_eq!(utf8[49], 1);
        // Not UTF-8 at all: refused locally rather than at the device.
        let err = ledger_offchain_envelope(&signer, &[0xff, 0xfe]).unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
    }

    #[test]
    fn offchain_envelope_rejects_payloads_the_device_would_reject() {
        let signer = Pubkey::from([2u8; 32]);
        // The app rejects `header.length == 0`.
        assert!(ledger_offchain_envelope(&signer, b"").is_err());
        // At the limit it is accepted; one byte over it is not. The binding cap
        // comes from solana-remote-wallet's send-side guard, not the device.
        let at_limit = vec![b'a'; MAX_OFFCHAIN_PAYLOAD_LEN];
        assert!(ledger_offchain_envelope(&signer, &at_limit).is_ok());
        let over = vec![b'a'; MAX_OFFCHAIN_PAYLOAD_LEN + 1];
        assert!(ledger_offchain_envelope(&signer, &over).is_err());
        // And the whole envelope still fits what remote-wallet will send.
        assert_eq!(
            ledger_offchain_envelope(&signer, &at_limit).unwrap().len(),
            1215
        );
    }

    #[test]
    fn unsupported_operation_names_blind_signing() {
        // APDU 0x6808: non-ASCII off-chain message with blind signing disabled.
        use solana_remote_wallet::ledger_error::LedgerError;
        let err = map_rw_err(RemoteWalletError::LedgerError(LedgerError::SdkNotSupported));
        assert!(matches!(err, SignerError::SigningFailed(_)));
        assert!(
            err.detail_string().contains("blind signing"),
            "the remedy has to be in the message, got: {}",
            err.detail_string()
        );
    }

    #[test]
    fn app_protocol_mismatch_is_not_reported_as_a_locked_device() {
        // Nano Gen5 with app returning 7-byte config when 5 bytes expected: must not
        // report as device state fault (locked), but as version incompatibility.
        let err = map_rw_err(RemoteWalletError::Protocol("Version packet size mismatch"));
        assert!(matches!(err, SignerError::NotAvailable(_)));
        let detail = err.detail_string();
        assert!(
            !detail.contains("locked"),
            "must not blame the device state, got: {detail}"
        );
        assert!(
            detail.contains("solana-remote-wallet"),
            "must name the incompatible component, got: {detail}"
        );
        // And the genuinely ambiguous case still says both things.
        let ambiguous = map_rw_err(RemoteWalletError::Protocol("Unknown error"));
        assert!(ambiguous.detail_string().contains("locked"));
    }

    #[test]
    fn locked_device_maps_to_not_available_and_says_so() {
        // Locked device (Nano Gen5): transport answers but app-level command does not,
        // arriving as unclassified protocol error. Must not report as signing failure.
        let err = map_rw_err(RemoteWalletError::Protocol("Unknown error"));
        assert!(matches!(err, SignerError::NotAvailable(_)));
        // The caller cannot see the device screen, so the remedy has to be in
        // the message. `detail_string` is what surfaces it (Display is redacted).
        assert!(
            err.detail_string().contains("locked"),
            "a locked device must be described as locked, got: {}",
            err.detail_string()
        );
    }

    #[test]
    fn unclassified_protocol_error_also_names_the_busy_device() {
        // Protocol(_) when another process holds device (Nano Gen5 with Ledger Live,
        // stray script): enumeration succeeds, handle opens. Must offer busy device
        // as a cause, not just "unlock it".
        let err = map_rw_err(RemoteWalletError::Protocol("Unknown error"));
        let detail = err.detail_string();
        assert!(
            detail.contains("another application"),
            "a busy device must be offered as a cause, got: {detail}"
        );
        assert!(
            detail.contains("Ledger Live"),
            "the remedy has to name the usual culprit, got: {detail}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn hid_error_names_udev_on_linux() {
        // A missing udev rule and an unplugged cable produce the same HID error,
        // and only one of them is worth checking the cable for.
        let err = map_rw_err(RemoteWalletError::Hid("open failed".to_string()));
        assert!(
            err.detail_string().contains("udev"),
            "got: {}",
            err.detail_string()
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn hid_error_omits_the_udev_hint_off_linux() {
        // udev does not exist here; offering it would be noise.
        let err = map_rw_err(RemoteWalletError::Hid("open failed".to_string()));
        assert!(!err.detail_string().contains("udev"));
    }

    #[test]
    fn hid_error_points_at_a_busy_device_not_just_the_cable() {
        // A HID-layer failure is far more often a held handle than a real
        // disconnect. Reporting only the disconnect sends the user to check the
        // one thing that is fine.
        let err = map_rw_err(RemoteWalletError::Hid("device open failed".to_string()));
        assert!(matches!(err, SignerError::NotAvailable(_)));
        let detail = err.detail_string();
        assert!(
            detail.contains("another application"),
            "a held HID handle must be offered as a cause, got: {detail}"
        );
    }

    #[test]
    fn connect_without_device_fails_cleanly() {
        // Contract: with no usable Ledger, connect returns an error cleanly and
        // never hangs or panics. We accept any Err (the exact variant depends on
        // the host's HID subsystem — e.g. NotAvailable when absent, but a CI
        // runner without libhidapi may surface something else). If a device *is*
        // attached, connect succeeds and there is nothing to assert.
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match LedgerSigner::connect(None, false, None) {
            Ok(_) | Err(_) => {}
        }
        idle();
    }

    #[test]
    fn a_decline_after_a_launch_is_not_retried() {
        let rig = Rig::attach(&["/a"]);
        {
            let mut bench = rig.hardware.bench();
            bench.faulty.push("/a".to_string());
            bench.declined.push("/a".to_string());
        }
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(LedgerConfig {
            confirm_pubkey_on_device: true,
            auto_open_app: true,
            ..quiet(Some("/a"))
        })
        .expect_err("declined");
        assert!(matches!(err, SignerError::UserRejected(_)), "got: {err:?}");
        assert_eq!(
            rig.calls(),
            [
                "resolve /a",
                "open /a",
                "launch",
                "resolve /a",
                "open /a",
                "confirm /a",
                "close /a"
            ]
        );
    }

    #[test]
    fn a_ledger_held_elsewhere_is_not_unenumerated() {
        let rig = Rig::attach(&["/a"]);
        rig.hardware.bench().held_elsewhere.push("/a".to_string());
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(quiet(None)).expect_err("another app holds /a");
        assert_eq!(err.detail_string(), unopenable_error().detail_string());
        assert_eq!(rig.calls(), ["resolve", "open /a"]);
    }

    #[test]
    fn every_session_on_the_device_closes_before_launch() {
        let rig = Rig::attach(&["/usb/a@0"]);
        let _named = connect(quiet(Some("/usb/a@0")));
        rig.hardware.bench().attached = vec![vec!["/usb/a@1".to_string()]];
        let _sibling = connect(quiet(Some("/usb/a@1")));
        rig.calls();
        {
            let mut bench = rig.hardware.bench();
            bench.attached = vec![vec!["/usb/a@0".to_string(), "/usb/a@1".to_string()]];
            bench.faulty = ["/usb/a@0", "/usb/a@0"].map(String::from).to_vec();
            bench.app_running = true;
        }
        assert!(idle(), "the device thread kept its claim");
        LedgerSigner::connect_with(LedgerConfig {
            auto_open_app: true,
            ..quiet(Some("/usb/a@0"))
        })
        .expect_err("the device was lost");
        assert_eq!(
            rig.calls(),
            [
                "pubkey /usb/a@0",
                "close /usb/a@0",
                "open /usb/a@0",
                "resolve /usb/a@0",
                "close /usb/a@1",
                "launch"
            ]
        );
    }

    #[test]
    fn every_session_on_the_device_closes_before_confirm() {
        let rig = Rig::attach(&["/usb/a@0"]);
        let _named = connect(quiet(Some("/usb/a@0")));
        rig.hardware.bench().attached = vec![vec!["/usb/a@1".to_string()]];
        let _sibling = connect(quiet(Some("/usb/a@1")));
        rig.hardware.bench().attached = vec![vec!["/usb/a@0".to_string(), "/usb/a@1".to_string()]];
        rig.calls();
        let _confirmed = connect(LedgerConfig {
            confirm_pubkey_on_device: true,
            ..quiet(Some("/usb/a@0"))
        });
        let mut calls = rig.calls();
        calls[1..3].sort();
        assert_eq!(
            calls,
            [
                "resolve /usb/a@0",
                "close /usb/a@0",
                "close /usb/a@1",
                "open /usb/a@0",
                "confirm /usb/a@0"
            ]
        );
    }

    #[test]
    fn a_failed_listing_before_launch_keeps_the_connect_error() {
        let rig = Rig::attach(&["/a"]);
        let _held = connect(quiet(Some("/a")));
        rig.calls();
        {
            let mut bench = rig.hardware.bench();
            bench.faulty = ["/a", "/a"].map(String::from).to_vec();
            bench.listings = 0;
            bench.unlisted_after = Some(1);
        }
        assert!(idle(), "the device thread kept its claim");
        let err = LedgerSigner::connect_with(LedgerConfig {
            auto_open_app: true,
            ..quiet(Some("/a"))
        })
        .expect_err("the device was lost");
        assert!(
            matches!(&err, SignerError::NotAvailable(d) if d == "device lost"),
            "got: {err:?}"
        );
        assert_eq!(rig.calls(), ["pubkey /a", "close /a", "open /a"]);
    }
}
