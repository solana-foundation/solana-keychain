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
//! `solana-remote-wallet` is single-threaded: its `RemoteWalletManager` and
//! `LedgerWallet` handles are reference-counted with [`std::rc::Rc`] and wrap a
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
//! ## One session, and what that costs
//!
//! The device thread caches **one** session at a time. Two consequences worth
//! knowing before designing around this backend.
//!
//! One on-device confirmation at a time, per process. Signing serializes through
//! the single actor, and a dispatched APDU cannot be cancelled, so a second
//! signing request arriving while the device is mid-prompt fails fast rather
//! than queueing behind a human who may never answer.
//!
//! Two physical Ledgers cannot be used concurrently. Alternating between signers
//! bound to different devices thrashes the one cached session: each command
//! re-establishes against its own `host_device_path`, so throughput collapses,
//! and a signature produced on the wrong device fails closed at
//! `verify_or_reject` rather than being attached. It is safe, but it is not
//! usable. Sequential use of one device at a time is the supported shape.
//!
//! TODO: replace the single `Option<Session>` with a map keyed by host device
//! path, so concurrent devices each keep their own handle. Deliberately not done
//! alongside the re-establish logic in [`with_session`]: the interaction between
//! "rebuild a missing session" and "which of several sessions is missing" is
//! subtle enough to want its own change.
//!
//! Works under any of `sdk-v2`/`sdk-v3`/`sdk-v4`. The backend needs
//! `solana-remote-wallet` 4.x — the first line carrying the Nano Gen5 product
//! IDs — whose solana-* crates do not match the ones `sdk-v2`/`sdk-v3` select.
//! That costs nothing here: pubkeys and signatures cross to the selected SDK as
//! raw bytes (see [`signature_bytes`]), so the two majors coexist in the
//! dependency graph and no type is ever required to unify.

mod dashboard;

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use solana_derivation_path::DerivationPath;
use solana_remote_wallet::ledger::LedgerWallet;
use solana_remote_wallet::remote_wallet::{
    initialize_wallet_manager, RemoteWallet, RemoteWalletError, RemoteWalletType,
};

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
        host_device_path: Option<String>,
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
        host_device_path: Option<String>,
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
        host_device_path: Option<String>,
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Liveness probe: can we read the pubkey without on-device confirmation?
    IsAvailable {
        /// Released when the actor drops this command, so a caller-side
        /// timeout cannot free a device that is still busy.
        claim: DeviceClaim,
        path_str: String,
        host_device_path: Option<String>,
        reply: Sender<bool>,
    },
    /// Is any Ledger attached, regardless of whether it is usable?
    ///
    /// Exists so callers never have to touch `hidapi` themselves; see
    /// [`device_channel`] for why that matters.
    IsAttached { reply: Sender<bool> },
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
/// crashes the process. Single operations always looked fine, which is exactly
/// what made this read as a flaky test rather than a lifecycle bug. Confirmed
/// from the crash report -- the faulting frames are the chain above.
///
/// One thread that never exits keeps every HID source scheduled on a run loop
/// that stays alive, which is the only arrangement IOKit tolerates. It is also
/// the right shape anyway: a Ledger services one APDU exchange at a time, so
/// serialising through a single thread costs nothing.
static DEVICE_THREAD: std::sync::OnceLock<Sender<DeviceCommand>> = std::sync::OnceLock::new();

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
            .spawn(move || device_thread(cmd_rx))
            .expect("failed to spawn the Ledger device thread");
        cmd_tx
    })
}

/// A [`SolanaSigner`] backed by a Ledger hardware wallet.
///
/// Cheap to create and drop: it holds no thread and no device handle, only the
/// cached pubkey and the derivation path to use. All device work happens on the
/// shared thread described at [`DEVICE_THREAD`].
pub struct LedgerSigner {
    pubkey: Pubkey,
    path_str: String,
    /// The device this signer was opened against, carried on every later
    /// command so a lost session re-establishes against the same one rather
    /// than whichever Ledger happens to be attached.
    host_device_path: Option<String>,
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
    /// [`SignerError::NotAvailable`] listing each device's path so the caller can
    /// retry with a specific one.
    ///
    /// Naming a path does **not** make two devices usable concurrently. The
    /// device thread caches one session, so alternating between signers bound to
    /// different devices re-establishes on every command. It stays correct -- a
    /// signature from the wrong device fails closed at verification -- but it is
    /// not a supported concurrency model. See the module documentation.
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

        let requested_device = host_device_path.clone();
        // A connect can reach the user too, so it takes the same claim rather
        // than racing a signature already at the confirm screen.
        let claim = DeviceClaim::acquire()?;
        let pubkey_bytes = request_on(device_channel(), timeout, claim, |claim, reply| {
            DeviceCommand::Connect {
                claim,
                path_str: path_str.clone(),
                confirm_pubkey_on_device,
                host_device_path,
                auto_open_app,
                reply,
            }
        })?;

        Ok(Self {
            pubkey: Pubkey::from(pubkey_bytes),
            path_str,
            host_device_path: requested_device,
            signing_timeout,
        })
    }

    /// The device this signer was opened against, if one was named.
    pub fn host_device_path(&self) -> Option<&str> {
        self.host_device_path.as_deref()
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
        let host_device_path = self.host_device_path.clone();
        let timeout = self.signing_timeout;
        // One process serializes to one on-device confirmation at a time. Claim
        // the device before enqueueing, so a racing caller fails fast instead of
        // waiting out its whole timeout behind someone else's prompt. Held until
        // this function returns, by any path.
        let claim = DeviceClaim::acquire()?;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), timeout, claim, |claim, reply| {
                DeviceCommand::SignOffchainMessage {
                    claim,
                    path_str,
                    message: serialized,
                    host_device_path,
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
    /// `false` rather than blocking when the device thread is wedged.
    async fn is_available(&self) -> bool {
        let path_str = self.path_str.clone();
        let host_device_path = self.host_device_path.clone();
        tokio::task::spawn_blocking(move || {
            // Probe, not an operation: if someone else holds the device, report
            // "not available" rather than queueing behind their prompt.
            let Some(claim) = DeviceClaim::try_acquire() else {
                return false;
            };
            let (reply_tx, reply_rx) = mpsc::channel();
            if device_channel()
                .send(DeviceCommand::IsAvailable {
                    claim,
                    path_str,
                    host_device_path,
                    reply: reply_tx,
                })
                .is_err()
            {
                return false;
            }
            match reply_rx.recv_timeout(OPS_TIMEOUT) {
                Ok(available) => available,
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
        let host_device_path = self.host_device_path.clone();
        let timeout = self.signing_timeout;
        // One process serializes to one on-device confirmation at a time. Claim
        // the device before enqueueing, so a racing caller fails fast instead of
        // waiting out its whole timeout behind someone else's prompt. Held until
        // this function returns, by any path.
        let claim = DeviceClaim::acquire()?;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), timeout, claim, |claim, reply| {
                DeviceCommand::SignTransactionMessage {
                    claim,
                    path_str,
                    message,
                    host_device_path,
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
/// This deliberately does not use `solana_offchain_message`, because that crate
/// and the Ledger app implement different layouts and the crate's output is
/// rejected outright. Verified against a real Nano Gen5: the crate's envelope
/// returns APDU `SolanaInvalidMessageHeader`, exactly as raw unwrapped bytes do,
/// which is why simply "wrapping the payload" did not fix off-chain signing.
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
    SignerError::NotAvailable(
        "Ledger is busy with another operation or awaiting on-device confirmation".to_string(),
    )
}

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
/// ## Why this is not a bool check
///
/// It used to be: callers read `DEVICE_BUSY` and returned early if set, and the
/// *actor* raised the flag once it dequeued a command. That is check-then-act,
/// and it does not hold. Two callers could both read `false`, both enqueue, and
/// the second would then wait its entire signing timeout behind the first
/// caller's confirmation prompt -- which is precisely the stall the flag exists
/// to prevent, so the fail-fast contract was strongest exactly when it was
/// needed least.
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
/// dropped, which the actor detects when it finally answers: see
/// [`respond`], which drops the cached session so the next connect
/// re-establishes rather than reusing a handle left mid-exchange.
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

/// The device-actor thread body. Owns the single-threaded `solana-remote-wallet`
/// handles and serves [`DeviceCommand`]s until the command channel closes.
/// Establish a device session: enumerate, select, and read the pubkey.
///
/// Runs only on the device thread. Returns the wallet handle so the caller can
/// cache it for subsequent commands.
fn establish_session(
    path: &DerivationPath,
    confirm_pubkey_on_device: bool,
    host_device_path: Option<&str>,
) -> Result<(Rc<LedgerWallet>, [u8; 32]), SignerError> {
    // A failure to bring up the HID subsystem is an *availability* problem,
    // not a signing failure — map it to NotAvailable directly rather than
    // letting map_rw_err's catch-all bucket it as SigningFailed (which would
    // also make the no-device unit test panic on CI runners lacking libhidapi).
    let manager = initialize_wallet_manager()
        .map_err(|e| SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}")))?;
    let count = manager.update_devices().map_err(map_rw_err)?;
    if count == 0 {
        return Err(no_ledger_enumerated_error());
    }

    // `list_devices` filters to valid Ledger wallets by VID/PID + HID usage,
    // but it also enumerates Trezor (and optionally Keystone) devices. The
    // `wallet_type` variant is what identifies a Ledger — not the model,
    // which is the device *name* ("nano-gen5", "nano-x", "stax", …) and never
    // "ledger". Taking the `Rc<LedgerWallet>` straight out of the variant
    // also removes the second `get_wallet`/`get_ledger` lookup by path.
    let ledgers: Vec<Rc<LedgerWallet>> = manager
        .list_devices()
        .into_iter()
        .filter_map(|d| match d.wallet_type {
            RemoteWalletType::Ledger(wallet) => Some(wallet),
            _ => None,
        })
        .collect();

    // Deterministic device selection: honor an explicit host path; otherwise
    // require exactly one device rather than silently picking the first (the
    // enumeration order is OS-dependent and unstable across re-plugs).
    let ledger = match host_device_path {
        Some(want) => ledgers
            .into_iter()
            .find(|w| hid_path(w).as_deref() == Some(want))
            .ok_or_else(|| {
                SignerError::NotAvailable(format!("no Ledger device at host path `{want}`"))
            })?,
        None => match ledgers.len() {
            0 => return Err(no_ledger_enumerated_error()),
            1 => ledgers.into_iter().next().expect("len == 1"),
            _ => {
                // `pretty_path` is the canonical Solana device locator
                // (`usb://ledger/<base pubkey>`) — stable across re-plugs,
                // unlike the OS HID path, so it is the useful half of the
                // disambiguation hint even though the path is what selects.
                let list = ledgers
                    .iter()
                    .map(|w| {
                        format!(
                            "  {} ({})",
                            hid_path(w).unwrap_or_else(|| "<unknown path>".to_string()),
                            w.pretty_path
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(SignerError::NotAvailable(format!(
                    "multiple Ledger devices connected; pass host_device_path to select one:\n{list}"
                )));
            }
        },
    };

    let pubkey = ledger
        .get_pubkey(path, confirm_pubkey_on_device)
        .map_err(map_rw_err)?;
    Ok((ledger, pubkey.to_bytes()))
}

/// Ledger USB vendor id.
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
        return SignerError::NotAvailable(
            "no Ledger device found (plug in, unlock, and open the Solana app)".to_string(),
        );
    }
    let pid_list = attached
        .iter()
        .map(|p| format!("0x{p:04x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let gen5 = attached.iter().any(|p| GEN5_PIDS.contains(p));
    let requirement = if gen5 {
        "This is a Nano Gen5, which requires solana-remote-wallet >= 4.1. A build that \
         resolved 4.0.x -- which is what the Solana 3.x crate line selects -- cannot see it \
         at all."
    } else {
        "This build's solana-remote-wallet does not recognise that product id, so it never \
         enumerated the device. A newer solana-remote-wallet is likely required."
    };
    SignerError::NotAvailable(format!(
        "a Ledger device is attached (product id {pid_list}) but this build did not \
         enumerate it. {requirement} Run `cargo tree -i solana-remote-wallet` to see which \
         version your graph resolved.{LINUX_UDEV_HINT}"
    ))
}

/// A live device session, cached on the device thread between commands.
struct Session {
    wallet: Rc<LedgerWallet>,
    /// The host path this session was opened against, so a `Connect` asking for
    /// a *different* device re-establishes instead of silently using this one.
    host_device_path: Option<String>,
}

/// The device thread body. Runs for the life of the process.
///
/// Holds at most one open session and reuses it across commands, so repeated
/// `LedgerSigner::connect` calls do not re-enumerate HID. Any device error drops
/// the session, so the next connect re-establishes rather than reusing a handle
/// to a device that has been unplugged, locked or switched apps.
fn device_thread(cmd_rx: Receiver<DeviceCommand>) {
    let mut session: Option<Session> = None;

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
                host_device_path,
                auto_open_app,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    // Reuse only when it is the same device *and* the caller
                    // does not need an on-screen confirmation, which by
                    // definition has to reach the device.
                    if let Some(existing) = session
                        .as_ref()
                        .filter(|s| s.host_device_path == host_device_path)
                        .filter(|_| !confirm_pubkey_on_device)
                    {
                        if let Ok(pubkey) = existing.wallet.get_pubkey(&path, false) {
                            return Ok(pubkey.to_bytes());
                        }
                        // The cached handle is stale; fall through and rebuild.
                    }
                    session = None;
                    let attempt = |host: Option<&str>| {
                        establish_session(&path, confirm_pubkey_on_device, host)
                    };
                    let mut connected = attempt(host_device_path.as_deref());

                    // The Solana app may simply not be running. Once the user
                    // has unlocked with their PIN, auto-launch it for them via
                    // the BOLOS dashboard instead of erroring out with "open the
                    // Solana app", then retry across the USB re-enumeration that
                    // launching an app triggers. Best-effort: if the dashboard is
                    // unreachable we keep the original connect error. Declining
                    // the launch prompt on-device, though, is a real user
                    // decision — surface it.
                    if connected.is_err() && auto_open_app {
                        match dashboard::ensure_solana_app_open(host_device_path.as_deref()) {
                            // The dashboard can identify a locked device exactly
                            // (APDU 0x5515) where the Solana-app path cannot. When
                            // it does, prefer that definitive answer over the
                            // hedged "locked or busy" one the connect produced.
                            Err(e @ SignerError::NotAvailable(_))
                                if e.detail_string().contains("is locked") =>
                            {
                                return Err(e)
                            }
                            Ok(_launched) => {
                                for _ in 0..20 {
                                    std::thread::sleep(std::time::Duration::from_millis(250));
                                    connected = attempt(host_device_path.as_deref());
                                    if connected.is_ok() {
                                        break;
                                    }
                                }
                            }
                            Err(e @ SignerError::UserRejected(_)) => return Err(e),
                            Err(e) => log::debug!(
                                "could not auto-open the Solana app ({e:?}); continuing"
                            ),
                        }
                    }

                    let (wallet, pubkey_bytes) = connected?;
                    session = Some(Session {
                        wallet,
                        host_device_path,
                    });
                    Ok(pubkey_bytes)
                });
                let _ = reply.send(result);
            }

            DeviceCommand::SignTransactionMessage {
                claim: _claim,
                path_str,
                message,
                host_device_path,
                reply,
            } => {
                let result = with_session(
                    &mut session,
                    &path_str,
                    host_device_path.as_deref(),
                    |wallet, path| {
                        wallet
                            .sign_message(path, &message)
                            .map(signature_bytes)
                            .map_err(map_rw_err)
                    },
                );
                let _ = reply.send(result);
            }

            DeviceCommand::SignOffchainMessage {
                claim: _claim,
                path_str,
                message,
                host_device_path,
                reply,
            } => {
                let result = with_session(
                    &mut session,
                    &path_str,
                    host_device_path.as_deref(),
                    |wallet, path| {
                        wallet
                            .sign_offchain_message(path, &message)
                            .map(signature_bytes)
                            .map_err(map_rw_err)
                    },
                );
                let _ = reply.send(result);
            }

            DeviceCommand::IsAvailable {
                claim: _claim,
                path_str,
                host_device_path,
                reply,
            } => {
                let ok = with_session(
                    &mut session,
                    &path_str,
                    host_device_path.as_deref(),
                    |wallet, path| wallet.get_pubkey(path, false).map_err(map_rw_err),
                )
                .is_ok();
                let _ = reply.send(ok);
            }

            DeviceCommand::IsAttached { reply } => {
                const LEDGER_VID: u16 = 0x2c97;
                let attached = hidapi::HidApi::new()
                    .map(|api| api.device_list().any(|d| d.vendor_id() == LEDGER_VID))
                    .unwrap_or(false);
                let _ = reply.send(attached);
            }
        }
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
/// The bug this fixes: the old code dropped the session on *any* error, which
/// included [`SignerError::UserRejected`]. But a rejection is an app-level
/// answer over a perfectly healthy transport -- the user read the screen and
/// pressed no. Throwing the session away made the very next signature fail with
/// "no Ledger session; connect first", so declining one transaction bricked the
/// signer until the caller built a new one. Rejecting a transaction is a normal
/// thing a user does, not a fault.
///
/// Only availability and signing faults, which is what `map_rw_err` produces for
/// a device that is gone, locked, held by another process or off in a different
/// app, mean the handle is worthless.
fn session_action(error: &SignerError) -> SessionAction {
    match error {
        SignerError::NotAvailable(_) | SignerError::SigningFailed(_) => SessionAction::Drop,
        // UserRejected above all, plus ConfigError, which never reached the wire.
        _ => SessionAction::Keep,
    }
}

/// Run `f` against the cached session, re-establishing it if it is gone.
///
/// Two behaviours, both of which used to be missing.
///
/// It re-establishes. Only the `connect` constructor ever created a session, so
/// once one was dropped, every later command on an existing signer failed with
/// "no Ledger session; connect first" forever -- the signer could not recover
/// from an unplug/replug even though the device was back. Now a missing session
/// is rebuilt against the host path this signer was opened with.
///
/// That is safe because it cannot silently move to a different device: the
/// pubkey cached at connect is what every returned signature is verified
/// against, so a re-established session on the wrong Ledger fails closed at
/// `verify_or_reject` rather than signing with an unexpected key. The explicit
/// host-path check below turns most of those into a legible error first.
///
/// It re-establishes *without* the dashboard auto-launch. `establish_session`
/// does not launch anything; only the `Connect` arm does. Signing is not the
/// moment to start writing app-management APDUs to a device on its own
/// initiative.
fn with_session<T>(
    session: &mut Option<Session>,
    path_str: &str,
    host_device_path: Option<&str>,
    f: impl FnOnce(&Rc<LedgerWallet>, &DerivationPath) -> Result<T, SignerError>,
) -> Result<T, SignerError> {
    let path = DerivationPath::from_absolute_path_str(path_str)
        .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

    // A session opened against a different device is not ours to use. See the
    // two-device limitation on the module doc: one cached session means
    // alternating signers thrash it, and this is where that shows up.
    if session
        .as_ref()
        .is_some_and(|active| active.host_device_path.as_deref() != host_device_path)
    {
        *session = None;
    }

    if session.is_none() {
        let (wallet, _pubkey) = establish_session(&path, false, host_device_path)?;
        *session = Some(Session {
            wallet,
            host_device_path: host_device_path.map(str::to_string),
        });
    }
    let active = session.as_ref().expect("just established");

    let result = f(&active.wallet, &path);
    if let Err(error) = &result {
        if session_action(error) == SessionAction::Drop {
            *session = None;
        }
    }
    result
}

/// The OS HID path of a Ledger wallet's own device handle.
///
/// `solana-remote-wallet` 4.x makes `Device::path` and `Device::info`
/// crate-private, so the value that used to be read as
/// `Device::host_device_path` is recovered from the wallet's own `hidapi`
/// handle instead. Same string, same format — and the same one
/// [`dashboard::ensure_solana_app_open`] matches against.
fn hid_path(wallet: &LedgerWallet) -> Option<String> {
    let info = wallet.device.get_device_info().ok()?;
    info.path().to_str().ok().map(str::to_string)
}

/// Extract the 64 raw bytes of a `solana-remote-wallet` signature so it can be
/// rebuilt as the SDK-version-selected [`Signature`] type (byte-level bridge —
/// no cross-version type unification required).
///
/// Taken as `impl AsRef<[u8]>` rather than naming `solana_signature::Signature`:
/// under `sdk-v4` the `solana-signature` crate is bundled inside `solana-sdk`
/// and is not a direct dependency to name.
fn signature_bytes(sig: impl AsRef<[u8]>) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
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
        // An unclassified protocol error means the transport answered but the
        // app-level command did not. Two different states produce it and the
        // error carries nothing that separates them:
        //
        //   1. The device is locked. Observed on a Nano Gen5 that auto-locked
        //      between operations: every call failed as `Protocol("Unknown error")`.
        //   2. Another process holds the device. Observed on a Nano Gen5 with
        //      Ledger Live running: enumeration succeeds, so this is not
        //      `NoDeviceFound`, and the handle opens, so it is not `Hid`, but no
        //      app-level command completes.
        //
        // Reporting either as a *signing* failure is misleading — nothing was
        // signed and nothing is wrong with the transaction. It is `NotAvailable`
        // for the same reason "no device" is. Since we cannot tell the two
        // apart here, the message names both remedies: claiming only "locked"
        // sends anyone with Ledger Live open to re-enter a PIN that was never
        // the problem.
        // Not every `Protocol(_)` is a device-state problem, and treating them
        // alike sends the user to unlock a device that is already unlocked.
        //
        // This one is an app-protocol incompatibility, confirmed on a Nano Gen5
        // (PID 0x8000) that was unlocked with the Solana app open and the BOLOS
        // dashboard answering normally. `GET_APP_CONFIGURATION` (0xe0 0x04)
        // returns status 0x9000 with a **7-byte** payload,
        // `00 00 01 10 00 00 00`, while `solana-remote-wallet` 4.2.2 requires
        // exactly 5 (`ledger.rs:349`, `if config.len() != 5`) and the deprecated
        // fallback answers 0x6a83. So `update_devices` fails and `list_devices`
        // returns nothing, on a device that is working perfectly.
        //
        // Nothing on this side can fix it: the check runs inside
        // `update_devices` with no hook to bypass. Naming it is all we can do,
        // and it is worth a great deal more than "unlock your device".
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
                 older Solana app); see docs/LEDGER.md."
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
            SignerError::NotAvailable(
                "Ledger did not answer. It is either locked — unlock it and open the Solana app — \
                 or another application is holding the device, so quit Ledger Live and any other \
                 wallet software. Then retry."
                    .to_string(),
            )
        }
        // APDU 0x6808. Observed on a Nano Gen5 running Solana app 1.16.0 when
        // signing an off-chain message whose payload is not printable ASCII: the
        // app refuses format 1 (LimitedUtf8) unless blind signing is enabled in
        // its settings. Upstream renders this as "Ledger operation not
        // supported", which is true and useless -- it names no remedy, and the
        // remedy is a setting the user can change in ten seconds.
        //
        // 0x6808 is a generic BOLOS "not supported", so this does not claim to
        // be the only cause; it offers the one that is overwhelmingly likely for
        // a signing call and says so.
        //
        // The wording mirrors what the device puts on screen -- "This transaction
        // cannot be clear-signed", with a "Go to settings" button -- so a user
        // looking at the device and a developer reading a log see the same words.
        // It also says the modal must be dismissed, because it stays up and
        // blocks every subsequent command, which otherwise reads as a hung
        // device.
        RemoteWalletError::LedgerError(LedgerError::SdkNotSupported) => SignerError::SigningFailed(
            "the Ledger could not clear-sign this, and blind signing is disabled in the \
                 Solana app's settings. The device shows \"This transaction cannot be \
                 clear-signed\" with a \"Go to settings\" prompt, which has to be dismissed \
                 before it will answer anything else. Blind signing is required for off-chain \
                 messages that are not printable ASCII, and for transactions the app cannot \
                 decode."
                .to_string(),
        ),
        other => SignerError::SigningFailed(format!("Ledger device error: {other}")),
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
            host_device_path: None,
            auto_open_app: false,
            reply,
        }
    }

    // ── F-1: the actor cannot stall a caller indefinitely ──

    #[test]
    fn a_command_times_out_at_its_tier_deadline() {
        let _guard = BUSY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DEVICE_BUSY.store(false, Ordering::SeqCst);
        // The receiver is held so `send` succeeds, but nothing ever serves it.
        // Before the deadline existed this never returned: the reply channel
        // used a plain blocking `recv()`, and the HID read the real actor sits
        // in has no timeout of its own.
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
        // The bug this pins: the check used to be a separate load before the
        // command was enqueued, and the flag was raised by the actor only once
        // it dequeued. Two callers could both read `false`, both enqueue, and
        // the second would then wait its entire signing timeout behind the
        // first one's confirmation prompt. The fail-fast contract failed exactly
        // when it mattered.
        //
        // Hammer it: many threads, one shared device, repeatedly. If admission
        // is not atomic, more than one thread holds a claim at the same moment
        // and `concurrent` climbs above 1.
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
        // The second-round defect. The claim was a caller-held guard, so it was
        // released when the caller returned -- including when it returned from a
        // *timeout*. But the actor can still be blocked in the untimed HID read
        // at that point, so the next caller would acquire, enqueue behind an
        // operation that is still running, and wait out its own full timeout.
        // The fail-fast promise quietly became a second full stall.
        //
        // Ownership now crosses the channel: the claim is moved into the command
        // and dropped by the actor when the work finishes. A wedged actor never
        // drops it, so it stays held.
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

    // ── F-14: a rejection must not kill the session ──

    #[test]
    fn a_rejection_keeps_the_session_and_a_transport_fault_drops_it() {
        // The defect: the old code dropped the session on any error, so
        // declining one transaction on the device made the next signature fail
        // with "no Ledger session; connect first". Rejecting is a normal thing
        // a user does over a perfectly healthy transport.
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
        let signer = LedgerSigner {
            pubkey: Pubkey::from([1u8; 32]),
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            host_device_path: Some("/dev/hidraw3".to_string()),
            signing_timeout: DEFAULT_SIGN_TIMEOUT,
        };
        assert_eq!(signer.host_device_path(), Some("/dev/hidraw3"));

        let sole = LedgerSigner {
            pubkey: Pubkey::from([2u8; 32]),
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            host_device_path: None,
            signing_timeout: DEFAULT_SIGN_TIMEOUT,
        };
        assert_eq!(sole.host_device_path(), None);
    }

    #[test]
    fn docs_quote_the_real_timeout_constants() {
        // docs/LEDGER.md said "5-minute" and "300s" for a while after
        // DEFAULT_SIGN_TIMEOUT was retuned to 120s. A reader trusting the prose
        // would have had a confirmation time out three minutes early. The doc
        // now names the constants instead of restating their values, and this
        // pins that: no bare duration may appear in the timeout table, and the
        // constants it names must be the ones that exist.
        let doc = include_str!("../../../docs/LEDGER.md");
        // `cargo ` is here because CLAUDE.md requires Rust commands to be
        // exposed through Just: the recipes carry flags a hand-written command
        // gets wrong. Two separate reviews caught this doc reintroducing raw
        // cargo, so it is now a test rather than a habit.
        for stale in [
            "5-minute signing timeout",
            "300s",
            "FAST_COMMAND_TIMEOUT",
            "cargo ",
        ] {
            assert!(
                !doc.contains(stale),
                "docs/LEDGER.md still contains `{stale}`, which no longer matches the code"
            );
        }
        for named in ["OPS_TIMEOUT", "DEFAULT_SIGN_TIMEOUT"] {
            assert!(
                doc.contains(named),
                "docs/LEDGER.md should name `{named}` rather than restate its value"
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

    // NOTE: signing paths require a physical device and are covered by the
    // hardware integration test (see `tests/test_ledger_integration.rs`), not
    // here — these unit tests only cover the pure logic that needs no device.

    // ── F-3: signature binding is what closes the device-swap race ──

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

        let mut raw = signature_bytes(good);
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

        let mut raw = signature_bytes(good);
        raw[63] ^= 0x80;
        let corrupted = Signature::from(raw);
        assert!(
            crate::signature_util::verify_or_reject(&corrupted, &pubkey, &message).is_err(),
            "a single flipped bit must fail verification"
        );
    }

    #[test]
    fn both_signing_paths_verify_before_returning() {
        // The tests above prove the predicate rejects bad signatures. They
        // cannot prove the signing paths still *call* it, and that is the
        // failure that would actually ship: a refactor dropping the check leaves
        // every test above green. So assert it against the source.
        //
        // Neither call is behind a `cfg`, and no other code path returns a
        // signature: the dashboard is reachable only from `Connect`, which
        // returns a pubkey.
        let src = include_str!("mod.rs");
        // Split off this test module first: its own source mentions the call,
        // and counting that would let the guard satisfy itself.
        let production = src
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("module has a test section");
        let verify_calls = production
            .matches("verify_or_reject(&signature, &self.pubkey")
            .count();
        assert_eq!(
            verify_calls, 2,
            "expected exactly one verify_or_reject in sign_message and one in \
             sign_transaction; found {verify_calls}"
        );
        for path in ["async fn sign_message", "async fn sign_transaction"] {
            let body = production.split(path).nth(1).expect("signing fn present");
            let end = body.find("\n    }").expect("fn body terminates");
            assert!(
                body[..end].contains("verify_or_reject"),
                "{path} must verify the device signature before returning it"
            );
        }
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

    // ── F-6: the silent-fork guard ──

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
    fn no_device_error_stays_plain_when_nothing_is_attached() {
        // With no Ledger-vendor device present the message must not speculate
        // about versions. On a machine with a Ledger attached this asserts the
        // enriched form instead, which is the branch that matters.
        let err = no_ledger_enumerated_error();
        assert!(matches!(err, SignerError::NotAvailable(_)));
        let detail = err.detail_string();
        if attached_ledger_pids().is_empty() {
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
    fn signature_bytes_roundtrips() {
        // The SDK-selected `Signature` stands in for `solana-remote-wallet`'s:
        // both are `solana-signature` types, and the bridge is byte-level, so
        // this exercises exactly the conversion the device path performs.
        let raw = [7u8; 64];
        let sig = Signature::from(raw);
        assert_eq!(signature_bytes(sig), raw);
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
        // Observed on hardware: a non-ASCII off-chain message with blind signing
        // disabled comes back as APDU 0x6808, which upstream renders as "Ledger
        // operation not supported". That is accurate and actionable for nobody.
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
        // Found on hardware: a Nano Gen5, unlocked, Solana app open, dashboard
        // answering, still failed to enumerate because the app returns a 7-byte
        // configuration vector where solana-remote-wallet 4.2.2 demands 5.
        // Reporting that as "unlock your device" is worse than useless, because
        // the user does it and nothing changes.
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
        // What a locked device actually produces, observed on a Nano Gen5 that
        // auto-locked mid-session: the transport answers, the app-level command
        // does not, and it arrives as an unclassified protocol error. It must not
        // be reported as a signing failure — nothing was signed.
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
        // The same `Protocol(_)` arm fires when another process holds the device
        // — observed on a Nano Gen5 with Ledger Live running, and again with a
        // stray script that had opened the device and not exited. Enumeration
        // succeeds and the handle opens, so neither `NoDeviceFound` nor `Hid`
        // catches it, and nothing in the error separates it from a locked
        // device. A message that offers only "unlock it" therefore sends the
        // user to re-enter a PIN that was never the problem, which is exactly
        // the loop this arm has to break.
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
        match LedgerSigner::connect(None, false, None) {
            Ok(_) | Err(_) => {}
        }
    }
}
