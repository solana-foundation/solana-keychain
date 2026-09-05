//! BOLOS dashboard operations (open / identify the running app) over USB-HID.
//!
//! `solana-remote-wallet` only speaks the **Solana app's** APDUs (get-pubkey,
//! sign, …). It has no way to *launch* the Solana app, and — worse — its
//! `get_ledger()` immediately calls Solana-app commands, so it fails outright
//! when the device is sitting on the dashboard (or in another app) after the
//! user has entered their PIN. Requiring the user to hand-navigate to the Solana
//! app before every `pay` command is exactly the UX papercut we want to remove.
//!
//! This module talks to the device's **dashboard** directly through `hidapi`,
//! reusing the Ledger APDU-over-HID transport framing (the same framing
//! `solana-remote-wallet` uses internally, which it does not expose publicly):
//!
//! - `getAppAndVersion` (`B0 01 00 00`) — which app is currently running;
//! - `openApp` (`E0 D8 00 00 "<name>"`) — launch a named app from the dashboard;
//! - `quitApp` (`B0 A7 00 00`) — return a running app to the dashboard.
//!
//! The PIN can never be entered or bypassed from the host — that is a hardware
//! invariant. All this does is spare the user the manual app navigation once the
//! device is unlocked.
//!
//! We open our own short-lived `hidapi` handle, do the dashboard exchange, and
//! drop it before `solana-remote-wallet` opens its own handle to the (now
//! running) Solana app. Opening an app makes the device re-enumerate on USB, so
//! the caller must tolerate a brief window before the Solana app answers.

use crate::error::SignerError;

/// Ledger USB vendor id.
const LEDGER_VID: u16 = 0x2c97;

/// APDU-over-HID transport framing constants (mirror `solana-remote-wallet`).
const APDU_TAG: u8 = 0x05;
const HID_TRANSPORT_HEADER_LEN: usize = 5;
const HID_PACKET_SIZE: usize = 64;

/// A Ledger exposes several HID interfaces; only the vendor-defined one speaks
/// the APDU transport. Same test `solana-remote-wallet` uses to pick it.
const HID_GLOBAL_USAGE_PAGE: u16 = 0xFF00;
const HID_USB_DEVICE_CLASS: i32 = 0;

fn is_apdu_interface(d: &hidapi::DeviceInfo) -> bool {
    d.usage_page() == HID_GLOBAL_USAGE_PAGE || d.interface_number() == HID_USB_DEVICE_CLASS
}

/// BOLOS dashboard APDUs.
const CLA_DASHBOARD: u8 = 0xb0;
const CLA_BOLOS: u8 = 0xe0;
const INS_GET_APP_AND_VERSION: u8 = 0x01;
const INS_OPEN_APP: u8 = 0xd8;
const INS_QUIT_APP: u8 = 0xa7;

const APDU_SUCCESS: u16 = 0x9000;

/// BOLOS status word for a locked device.
///
/// Observed on a Nano Gen5: with the device locked but plugged in,
/// `getAppAndVersion` answers `0x5515` and no app-level command completes. This
/// is the one signal that separates "locked" from "another process holds the
/// device" -- the Solana-app APDUs cannot tell them apart, which is why the
/// error for that case has to name both causes.
const APDU_DEVICE_LOCKED: u16 = 0x5515;

/// Name of the Solana embedded app as the dashboard reports and launches it.
pub const SOLANA_APP_NAME: &str = "Solana";

/// Ensure the **Solana** app is running on the connected Ledger, launching it
/// from the dashboard if needed.
///
/// Best-effort and side-effecting only when necessary:
/// - if the Solana app is already open, this is a no-op;
/// - if the device is on the dashboard, it sends the open-app APDU;
/// - if a *different* app is open, it quits to the dashboard first, then opens.
///
/// `host_device_path` selects a specific device by its OS HID path; pass `None`
/// to use the sole connected Ledger. Returns [`SignerError::NotAvailable`] if no
/// Ledger can be reached.
///
/// Returns `Ok(true)` if it **launched** the Solana app (the device will
/// re-enumerate on USB and the user must confirm on most firmware, so the caller
/// should retry the subsequent Solana-app connection for a short window), or
/// `Ok(false)` if the app was already running (no re-enumeration to wait for).
pub fn ensure_solana_app_open(host_device_path: Option<&str>) -> Result<bool, SignerError> {
    let api = hidapi::HidApi::new()
        .map_err(|e| SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}")))?;

    let device = open_ledger(&api, host_device_path)?;

    match current_app(&device)? {
        Some(app) if app == SOLANA_APP_NAME => Ok(false), // already there
        Some(app) if app == "BOLOS" || app.is_empty() => {
            open_app(&device, SOLANA_APP_NAME)?;
            Ok(true)
        }
        Some(_other) => {
            // A different app is open; return to the dashboard, then launch.
            // quitApp drops the connection, so re-open before launching.
            quit_app(&device)?;
            drop(device);
            let device = reopen_after_reenumerate(host_device_path)?;
            open_app(&device, SOLANA_APP_NAME)?;
            Ok(true)
        }
        None => {
            open_app(&device, SOLANA_APP_NAME)?;
            Ok(true)
        }
    }
}

/// Pick the device matching `want`, or nothing.
///
/// The Solana-app host path and this dashboard path are both HID paths on the
/// same physical device, but may name different *interfaces*, so an exact match
/// is not guaranteed even when the right device is attached. Hence the prefix
/// step.
///
/// What this must never do is fall back to an arbitrary device, which is what it
/// used to do: an exact-match miss selected `ledgers.first()`. With two Ledgers
/// attached that meant `ensure_solana_app_open` could quit the running app and
/// launch Solana on the device the caller did *not* name -- writing
/// app-management APDUs to the wrong security device, silently. Returning
/// `None` and letting the caller error is the only safe answer.
///
/// The prefix step is deliberately conservative: it takes the candidates sharing
/// the longest common prefix with `want` that ends on a path delimiter, and
/// accepts only if exactly one candidate does. Ambiguity resolves to `None`,
/// because guessing between two devices is the bug being fixed.
fn select_ledger(available: &[&str], want: &str) -> Option<usize> {
    if let Some(exact) = available.iter().position(|p| *p == want) {
        return Some(exact);
    }

    /// Length of the shared prefix, truncated back to the last delimiter so a
    /// coincidental partial component does not count as a match.
    fn shared_prefix_len(a: &str, b: &str) -> usize {
        // Bytes throughout, never a string slice. HID paths arrive via
        // `to_string_lossy` and can hold multibyte characters; if two paths
        // first differ *inside* one, the matching-byte count is not a char
        // boundary and `a[..common]` panics. Explicit device selection must
        // return an error in that case, never abort the process.
        let a = a.as_bytes();
        let b = b.as_bytes();
        let common = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
        const DELIMS: [u8; 4] = [b'/', b':', b'@', b'\\'];
        a[..common]
            .iter()
            .rposition(|byte| DELIMS.contains(byte))
            .map_or(0, |i| i + 1)
    }

    let best = available
        .iter()
        .map(|p| shared_prefix_len(p, want))
        .max()
        .unwrap_or(0);
    // The prefix must be nearly the whole path, so that what differs is a
    // trailing interface identifier and nothing more. A weak rule is worse than
    // no rule here: on Linux two *different* Ledgers appear as `/dev/hidraw2`
    // and `/dev/hidraw3`, which share `/dev/`, so anything that accepts a short
    // common prefix reintroduces exactly the wrong-device bug this replaces.
    // Requiring 80% means `/dev/` (5 of 12) is refused while a macOS
    // `IOService:/.../IOUSBHostInterface@0` vs `@1` pair (66 of 67) is accepted.
    if best * 5 < want.len() * 4 {
        return None;
    }
    let mut matching = available
        .iter()
        .enumerate()
        .filter(|(_, p)| shared_prefix_len(p, want) == best);
    let (idx, _) = matching.next()?;
    if matching.next().is_some() {
        return None; // ambiguous; never guess
    }
    Some(idx)
}

#[cfg(test)]
/// Which app the device reports running, without changing anything.
///
/// Read-only counterpart to [`ensure_solana_app_open`], for diagnosing a failed
/// connect: the `SignerError` cannot distinguish a locked device from a busy one
/// from the wrong app being open, and this answers the third case directly.
pub(super) fn running_app(host_device_path: Option<&str>) -> Result<Option<String>, SignerError> {
    let api = hidapi::HidApi::new()
        .map_err(|e| SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}")))?;
    let device = open_ledger(&api, host_device_path)?;
    current_app(&device)
}

#[cfg(test)]
/// Send one raw APDU and return `(payload, status_word)`, for diagnostics only.
///
/// Exists because `solana-remote-wallet` reports an app-protocol mismatch as an
/// opaque `Protocol("...")` string with the actual bytes discarded, and knowing
/// the payload length is the difference between "the device is locked" and "this
/// app version speaks a protocol the crate does not parse".
pub(super) fn probe_apdu(
    host_device_path: Option<&str>,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<(Vec<u8>, u16), SignerError> {
    let api = hidapi::HidApi::new()
        .map_err(|e| SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}")))?;
    let device = open_ledger(&api, host_device_path)?;
    exchange(&device, cla, ins, p1, p2, data)
}

/// Open the Ledger HID device, honoring an explicit host path or requiring a
/// single connected device.
fn open_ledger(
    api: &hidapi::HidApi,
    host_device_path: Option<&str>,
) -> Result<hidapi::HidDevice, SignerError> {
    let ledgers: Vec<&hidapi::DeviceInfo> = api
        .device_list()
        .filter(|d| d.vendor_id() == LEDGER_VID && is_apdu_interface(d))
        .collect();

    match host_device_path {
        Some(want) => {
            let paths: Vec<String> = ledgers
                .iter()
                .map(|d| d.path().to_string_lossy().into_owned())
                .collect();
            let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
            let idx = select_ledger(&refs, want).ok_or_else(|| {
                SignerError::NotAvailable(format!(
                    "no Ledger device at host path `{want}`; attached: {}",
                    if refs.is_empty() {
                        "none".to_string()
                    } else {
                        refs.join(", ")
                    }
                ))
            })?;
            ledgers[idx]
                .open_device(api)
                .map_err(|e| SignerError::NotAvailable(format!("cannot open Ledger: {e}")))
        }
        None => ledgers
            .first()
            .ok_or_else(|| {
                SignerError::NotAvailable("no Ledger device found (plug in and unlock)".to_string())
            })?
            .open_device(api)
            .map_err(|e| SignerError::NotAvailable(format!("cannot open Ledger: {e}"))),
    }
}

/// Re-enumerate and re-open after an app switch triggers USB re-enumeration.
/// Retries briefly because the device disappears and reappears.
fn reopen_after_reenumerate(
    host_device_path: Option<&str>,
) -> Result<hidapi::HidDevice, SignerError> {
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if let Ok(api) = hidapi::HidApi::new() {
            if let Ok(device) = open_ledger(&api, host_device_path) {
                return Ok(device);
            }
        }
    }
    Err(SignerError::NotAvailable(
        "Ledger did not re-enumerate after app switch".to_string(),
    ))
}

/// `getAppAndVersion` — returns the running app's name, or `None` if it can't be
/// determined. Response layout: `[format][name_len][name…][ver_len][ver…]…`.
fn current_app(device: &hidapi::HidDevice) -> Result<Option<String>, SignerError> {
    let (payload, status) = exchange(device, CLA_DASHBOARD, INS_GET_APP_AND_VERSION, 0, 0, &[])?;
    // A locked device is worth reporting exactly, because it is the one cause
    // the Solana-app APDUs cannot identify. Returning `Ok(None)` here, as this
    // used to, threw away the only unambiguous evidence we get.
    if status == APDU_DEVICE_LOCKED {
        return Err(SignerError::NotAvailable(
            "the Ledger is locked. Enter your PIN on the device, then retry.".to_string(),
        ));
    }
    if status != APDU_SUCCESS || payload.len() < 2 {
        return Ok(None);
    }
    let name_len = payload[1] as usize;
    let name = payload
        .get(2..2 + name_len)
        .map(|b| String::from_utf8_lossy(b).into_owned());
    Ok(name)
}

/// `openApp` — launch a named app from the dashboard.
///
/// Launching an installed app makes the device re-enumerate on USB the instant
/// it switches, which usually kills the response read before the `0x9000` comes
/// back. That is the normal, successful case — the caller confirms the launch by
/// reconnecting to the (now running) app. So a failed/absent response read here
/// is treated as success; only a clean on-device **rejection** (`0x6985`) or a
/// definite error status is surfaced.
fn open_app(device: &hidapi::HidDevice, name: &str) -> Result<(), SignerError> {
    write_apdu(device, CLA_BOLOS, INS_OPEN_APP, 0, 0, name.as_bytes())?;
    match read_apdu(device) {
        Ok((_, APDU_SUCCESS)) => Ok(()),
        Ok((_, status)) => Err(status_to_err(status, "open Solana app")),
        // Read failed because the app launched and the device re-enumerated.
        Err(_) => Ok(()),
    }
}

/// `quitApp` — return the running app to the dashboard.
fn quit_app(device: &hidapi::HidDevice) -> Result<(), SignerError> {
    // Quitting drops the USB connection; a read error here is expected and fine.
    let _ = exchange(device, CLA_DASHBOARD, INS_QUIT_APP, 0, 0, &[]);
    Ok(())
}

/// Map a non-success APDU status word onto a [`SignerError`].
fn status_to_err(status: u16, what: &str) -> SignerError {
    match status {
        0x6985 => SignerError::UserRejected(format!("{what}: rejected on device")),
        0x6807 | 0x6a83 => SignerError::NotAvailable(format!("{what}: app not installed")),
        other => SignerError::Other(format!("{what}: device returned status {other:#06x}")),
    }
}

/// One APDU exchange over the Ledger HID transport. Returns the response payload
/// (without the trailing status word) and the 2-byte status word.
///
/// Framing (per the Ledger transport protocol, macOS/Linux — no HID report-id
/// prefix byte): each 64-byte packet is
/// `[chan_hi=0x01][chan_lo=0x01][tag=0x05][seq_hi][seq_lo][payload…]`; the first
/// packet's payload begins with the 2-byte total APDU length, then
/// `CLA INS P1 P2 Lc data…`.
fn exchange(
    device: &hidapi::HidDevice,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<(Vec<u8>, u16), SignerError> {
    write_apdu(device, cla, ins, p1, p2, data)?;
    read_apdu(device)
}

fn write_apdu(
    device: &hidapi::HidDevice,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<(), SignerError> {
    // APDU body: CLA INS P1 P2 Lc <data>
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[cla, ins, p1, p2, data.len() as u8]);
    apdu.extend_from_slice(data);

    let total = apdu.len();
    let mut offset = 0usize;
    let mut seq: u16 = 0;
    while seq == 0 || offset < total {
        let mut packet = [0u8; HID_PACKET_SIZE];
        packet[0..5].copy_from_slice(&[0x01, 0x01, APDU_TAG, (seq >> 8) as u8, (seq & 0xff) as u8]);
        let mut pos = HID_TRANSPORT_HEADER_LEN;
        if seq == 0 {
            packet[pos] = (total >> 8) as u8;
            packet[pos + 1] = (total & 0xff) as u8;
            pos += 2;
        }
        let n = std::cmp::min(HID_PACKET_SIZE - pos, total - offset);
        packet[pos..pos + n].copy_from_slice(&apdu[offset..offset + n]);
        device
            .write(&packet)
            .map_err(|e| SignerError::NotAvailable(format!("Ledger HID write failed: {e}")))?;
        offset += n;
        seq += 1;
        if seq == 0xffff {
            return Err(SignerError::Other("APDU too large".to_string()));
        }
    }
    Ok(())
}

fn read_apdu(device: &hidapi::HidDevice) -> Result<(Vec<u8>, u16), SignerError> {
    let mut message = Vec::new();
    let mut message_size = 0usize;
    for chunk_index in 0..0xffffu16 {
        let mut chunk = [0u8; HID_PACKET_SIZE];
        let size = device
            .read_timeout(&mut chunk, 30_000)
            .map_err(|e| SignerError::NotAvailable(format!("Ledger HID read failed: {e}")))?;
        if size == 0 {
            return Err(SignerError::NotAvailable(
                "Ledger HID read timed out".to_string(),
            ));
        }
        if size < HID_TRANSPORT_HEADER_LEN
            || chunk[0] != 0x01
            || chunk[1] != 0x01
            || chunk[2] != APDU_TAG
        {
            return Err(SignerError::Other(
                "unexpected Ledger HID chunk".to_string(),
            ));
        }
        let seq = ((chunk[3] as u16) << 8) | chunk[4] as u16;
        if seq != chunk_index {
            return Err(SignerError::Other(
                "out-of-order Ledger HID chunk".to_string(),
            ));
        }
        let mut off = HID_TRANSPORT_HEADER_LEN;
        if seq == 0 {
            if size < 7 {
                return Err(SignerError::Other("short Ledger HID chunk".to_string()));
            }
            message_size = ((chunk[5] as usize) << 8) | chunk[6] as usize;
            off += 2;
        }
        message.extend_from_slice(&chunk[off..size]);
        if message.len() >= message_size {
            message.truncate(message_size);
            break;
        }
    }
    if message.len() < 2 {
        return Err(SignerError::Other("no APDU status word".to_string()));
    }
    let status = ((message[message.len() - 2] as u16) << 8) | message[message.len() - 1] as u16;
    message.truncate(message.len() - 2);
    Ok((message, status))
}

#[cfg(test)]
mod tests {
    use super::select_ledger;

    // ── F-3c: never open a device the caller did not name ──

    #[test]
    fn an_exact_path_wins() {
        let devices = ["/dev/hidraw2", "/dev/hidraw3"];
        assert_eq!(select_ledger(&devices, "/dev/hidraw3"), Some(1));
    }

    #[test]
    fn a_missing_path_is_never_substituted_by_another_device() {
        // The defect: an exact-match miss used to select `ledgers.first()`. With
        // two Ledgers attached that meant quitting an app and launching Solana
        // on the device the caller did not name.
        let devices = ["/dev/hidraw2", "/dev/hidraw3"];
        assert_eq!(
            select_ledger(&devices, "/dev/hidraw9"),
            None,
            "an unmatched path must resolve to nothing, not to some other device"
        );
    }

    #[test]
    fn a_sibling_interface_on_the_same_device_matches_by_prefix() {
        // The legitimate reason a prefix step exists: one physical Ledger
        // exposes several HID interfaces, and the Solana-app path may name a
        // different one than the dashboard path.
        let devices = ["IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1"];
        let want = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0";
        assert_eq!(select_ledger(&devices, want), Some(0));
    }

    #[test]
    fn two_devices_sharing_a_prefix_are_ambiguous_and_refused() {
        // Guessing between two devices is exactly the bug being fixed, so an
        // equal-length tie must resolve to None rather than to either one.
        let devices = [
            "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0",
            "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1",
        ];
        let want = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@7";
        assert_eq!(select_ledger(&devices, want), None);
    }

    #[test]
    fn a_multibyte_path_does_not_panic() {
        // The defect: `shared_prefix_len` counted matching *bytes* and then
        // sliced the string by that count. Two paths differing inside a
        // multibyte character gave a non-boundary index, so explicit device
        // selection panicked instead of returning an error. These pairs differ
        // mid-character on purpose.
        let cases: [(&str, &str); 4] = [
            ("/dev/ledger-é", "/dev/ledger-è"),
            ("IOService:/usb/ledger@café", "IOService:/usb/ledger@cafè"),
            ("/dev/日本語", "/dev/日本誤"),
            ("/dev/🔒a", "/dev/🔓a"),
        ];
        for (have, want) in cases {
            // Must not panic. Either answer is acceptable; aborting is not.
            let _ = select_ledger(&[have], want);
            let _ = select_ledger(&[want], have);
        }
    }

    #[test]
    fn a_multibyte_sibling_interface_still_matches() {
        // And the prefix rule keeps working when the shared part is multibyte:
        // these differ only in the trailing interface digit.
        let devices = ["IOService:/AppleT8103/usb-drd0/lédger@01100000/Interface@0"];
        let want = "IOService:/AppleT8103/usb-drd0/lédger@01100000/Interface@1";
        assert_eq!(select_ledger(&devices, want), Some(0));
    }

    #[test]
    fn a_shared_root_is_not_evidence_of_anything() {
        // Two unrelated devices both under /dev must not match each other.
        let devices = ["/dev/hidraw2"];
        assert_eq!(select_ledger(&devices, "/dev/hidraw9"), None);
        assert_eq!(select_ledger(&[], "/dev/hidraw2"), None);
    }

    use super::*;

    #[test]
    fn status_rejection_maps_to_user_rejected() {
        assert!(matches!(
            status_to_err(0x6985, "x"),
            SignerError::UserRejected(_)
        ));
    }

    #[test]
    fn status_missing_app_maps_to_not_available() {
        assert!(matches!(
            status_to_err(0x6807, "x"),
            SignerError::NotAvailable(_)
        ));
    }
}
