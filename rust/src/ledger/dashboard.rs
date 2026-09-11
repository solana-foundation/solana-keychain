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

use super::LEDGER_VID;
use crate::error::SignerError;

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

/// Locked device answers 0x5515; Solana-app APDUs cannot distinguish this from
/// device-held-by-process, so error must name both causes.
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
    let api = hidapi::HidApi::new().map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Ledger HID subsystem unavailable: {_e}");
        SignerError::NotAvailable(
            "the Ledger HID subsystem is unavailable. On Linux this is usually \
                 missing udev rules; otherwise no HID backend could be initialised."
                .to_string(),
        )
    })?;

    let device = open_ledger(&api, host_device_path)?;

    match current_app(&device)? {
        Some(app) if app == SOLANA_APP_NAME => Ok(false),
        Some(app) if app == "BOLOS" || app.is_empty() => {
            open_app(&device, SOLANA_APP_NAME)?;
            Ok(true)
        }
        Some(_other) => {
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
/// Paths may name different interfaces of the same device. Prefix matching
/// requires 80% common prefix ending on delimiter, accepting only if exactly
/// one matches. Ambiguity returns `None`, never an arbitrary device.
fn select_ledger(available: &[&str], want: &str) -> Option<usize> {
    if let Some(exact) = available.iter().position(|p| *p == want) {
        return Some(exact);
    }

    let best = available
        .iter()
        .map(|p| shared_prefix_len(p, want))
        .max()
        .unwrap_or(0);
    // The prefix must be nearly the whole path, so that what differs is a
    // trailing interface identifier and nothing more. See
    // [`is_sibling_interface`] for why the threshold is what it is.
    if !meets_sibling_threshold(best, want) {
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
    const DELIMS: [u8; 4] = *b"/:@\\";
    a[..common]
        .iter()
        .rposition(|byte| DELIMS.contains(byte))
        .map_or(0, |i| i + 1)
}

/// Is a shared prefix of `len` bytes enough to call two paths interfaces of one
/// device?
///
/// A weak rule is worse than no rule here: on Linux two *different* Ledgers
/// appear as `/dev/hidraw2` and `/dev/hidraw3`, which share `/dev/`, so
/// anything that accepts a short common prefix reintroduces exactly the
/// wrong-device bug this guards. Requiring 80% means `/dev/` (5 of 12) is
/// refused while a macOS `IOService:/.../IOUSBHostInterface@0` vs `@1` pair
/// (66 of 67) is accepted.
fn meets_sibling_threshold(len: usize, path: &str) -> bool {
    len * 5 >= path.len() * 4
}

/// Do two paths look like two interfaces of the same physical device?
///
/// Symmetric, because neither path is the one being asked for: it takes the
/// stricter of the two ratios so `sole_ledger` cannot get a different answer
/// depending on enumeration order.
fn is_sibling_interface(a: &str, b: &str) -> bool {
    let shared = shared_prefix_len(a, b);
    meets_sibling_threshold(shared, a) && meets_sibling_threshold(shared, b)
}

/// One attached Ledger APDU interface, as [`sole_ledger`] compares them.
#[derive(Clone, Copy)]
struct Candidate<'a> {
    path: &'a str,
    /// USB serial number, when the platform reports one. This is the only
    /// direct evidence that two interfaces belong to the same physical device.
    serial: Option<&'a str>,
}

/// Which device to use when the caller named none: exactly one, or an error.
///
/// One physical Ledger can pass [`is_apdu_interface`] filter multiple times
/// (multiple interfaces). Grouping by: (1) serial number when available (shared
/// by interfaces of one device, unique per device), or (2) path adjacency
/// (accepts IOUSBHostInterface@0/@1, rejects /dev/hidraw2/@3).
fn sole_ledger(candidates: &[Candidate<'_>]) -> Result<usize, SignerError> {
    if candidates.is_empty() {
        return Err(SignerError::NotAvailable(
            "no Ledger device found (plug in and unlock)".to_string(),
        ));
    }

    let mut devices: Vec<usize> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        let same_device_as = devices.iter().any(|&j| same_device(c, &candidates[j]));
        if !same_device_as {
            devices.push(i);
        }
    }

    match devices.len() {
        1 => Ok(devices[0]),
        n => {
            #[cfg(feature = "unsafe-debug")]
            log::error!(
                "multiple Ledger devices attached: {}",
                devices
                    .iter()
                    .map(|&i| candidates[i].path)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Err(super::multiple_devices_error(n))
        }
    }
}

/// Do two candidates belong to one physical device? Requires both signals to
/// agree; fails closed. Serial: Nano Gen5 reports "0001" on all interfaces
/// (fixed per model), so equality doesn't prove same device, only inequality.
/// Path adjacency: platform-dependent, weak toward "different" (safe).
fn same_device(a: &Candidate<'_>, b: &Candidate<'_>) -> bool {
    // A filled-in serial that differs is proof of two devices, whatever the
    // paths look like.
    if let (Some(x), Some(y)) = (a.serial, b.serial) {
        if !x.is_empty() && !y.is_empty() && x != y {
            return false;
        }
    }
    is_sibling_interface(a.path, b.path)
}

#[cfg(test)]
/// Which app the device reports running, without changing anything.
///
/// Diagnostic read-only counterpart: SignerError cannot distinguish locked from
/// busy from wrong-app, this answers the third directly.
pub(super) fn running_app(host_device_path: Option<&str>) -> Result<Option<String>, SignerError> {
    let api = hidapi::HidApi::new().map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Ledger HID subsystem unavailable: {_e}");
        SignerError::NotAvailable(
            "the Ledger HID subsystem is unavailable. On Linux this is usually \
                 missing udev rules; otherwise no HID backend could be initialised."
                .to_string(),
        )
    })?;
    let device = open_ledger(&api, host_device_path)?;
    current_app(&device)
}

#[cfg(test)]
/// Send one raw APDU and return `(payload, status_word)`, for diagnostics only.
///
/// `solana-remote-wallet` discards response bytes; payload length here
/// distinguishes device-locked from unsupported-protocol.
pub(super) fn probe_apdu(
    host_device_path: Option<&str>,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<(Vec<u8>, u16), SignerError> {
    let api = hidapi::HidApi::new().map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("Ledger HID subsystem unavailable: {_e}");
        SignerError::NotAvailable(
            "the Ledger HID subsystem is unavailable. On Linux this is usually \
                 missing udev rules; otherwise no HID backend could be initialised."
                .to_string(),
        )
    })?;
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

    let paths: Vec<String> = ledgers
        .iter()
        .map(|d| d.path().to_string_lossy().into_owned())
        .collect();

    let idx = match host_device_path {
        Some(want) => {
            let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
            select_ledger(&refs, want).ok_or_else(|| {
                // Paths go to log (filesystem/IOKit locators), count to error:
                // it tells the caller "nothing plugged in" vs "wrong path".
                #[cfg(feature = "unsafe-debug")]
                log::error!(
                    "no Ledger device at host path `{want}`; attached: {}",
                    if refs.is_empty() {
                        "none".to_string()
                    } else {
                        refs.join(", ")
                    }
                );
                SignerError::NotAvailable(format!(
                    "no Ledger device at the requested host path; {} Ledger interface(s) \
                     attached. Run `just rust-ledger-diagnose` to list them.",
                    refs.len()
                ))
            })?
        }
        // Never `.first()`. See `sole_ledger`.
        None => {
            let candidates: Vec<Candidate<'_>> = ledgers
                .iter()
                .zip(paths.iter())
                .map(|(d, path)| Candidate {
                    path: path.as_str(),
                    serial: d.serial_number(),
                })
                .collect();
            sole_ledger(&candidates)?
        }
    };

    ledgers[idx].open_device(api).map_err(|_e| {
        #[cfg(feature = "unsafe-debug")]
        log::error!("cannot open Ledger at `{}`: {_e}", paths[idx]);
        SignerError::NotAvailable(
            "cannot open the Ledger. Another application may be holding it -- quit \
                 Ledger Live and any other wallet software, then retry."
                .to_string(),
        )
    })
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
    // Locked device warrant exact reporting; it's the one state Solana-app APDUs
    // cannot distinguish.
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
/// Device re-enumerates on launch, usually killing the response read. That is
/// normal; caller confirms launch by reconnecting. Response read failure here
/// is success; only on-device rejection (0x6985) or definite error is reported.
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
        device.write(&packet).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Ledger HID write failed: {_e}");
            SignerError::NotAvailable(
                "writing to the Ledger failed. Either it was disconnected, or another \
                     application is holding the device."
                    .to_string(),
            )
        })?;
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
        let size = device.read_timeout(&mut chunk, 30_000).map_err(|_e| {
            #[cfg(feature = "unsafe-debug")]
            log::error!("Ledger HID read failed: {_e}");
            SignerError::NotAvailable(
                "reading from the Ledger failed. Either it was disconnected, or another \
                     application is holding the device."
                    .to_string(),
            )
        })?;
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

    #[test]
    fn an_exact_path_wins() {
        let devices = ["/dev/hidraw2", "/dev/hidraw3"];
        assert_eq!(select_ledger(&devices, "/dev/hidraw3"), Some(1));
    }

    #[test]
    fn a_missing_path_is_never_substituted_by_another_device() {
        // Must never substitute an unmatched path with another device.
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
        // Multibyte path differences must not panic; these pairs differ mid-
        // character on purpose to test that.
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

    fn candidate<'a>(path: &'a str, serial: Option<&'a str>) -> Candidate<'a> {
        Candidate { path, serial }
    }

    #[test]
    fn one_attached_ledger_is_used_without_an_explicit_path() {
        let c = [candidate("/dev/hidraw2", Some("0001"))];
        assert_eq!(sole_ledger(&c).unwrap(), 0);
    }

    #[test]
    fn several_interfaces_of_one_device_are_still_one_device() {
        // One physical Ledger passes filter multiple times; platform-provided
        // serial is direct evidence they are the same device.
        let c = [
            candidate(
                "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0",
                Some("0001"),
            ),
            candidate(
                "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1",
                Some("0001"),
            ),
        ];
        assert_eq!(
            sole_ledger(&c).unwrap(),
            0,
            "two interfaces on one device must not read as two devices"
        );
    }

    #[test]
    fn a_ledger_serial_is_not_an_identity() {
        // Nano Gen5 reports "0001" on all interfaces (fixed per model, not per
        // unit); two different Ledgers report same serial, so equality cannot
        // prove same device.
        let two_devices = [
            candidate("DevSrvsID:4294981014", Some("0001")),
            candidate("/dev/hidraw7", Some("0001")),
        ];
        assert!(
            sole_ledger(&two_devices).is_err(),
            "equal serials on unrelated paths must not fuse two devices into one"
        );

        // Inequality is still trusted, in the one direction it can be:
        // different serials mean different devices even on adjacent paths.
        let adjacent_but_distinct = [
            candidate(
                "IOService:/usb/ledger@01100000/IOUSBHostInterface@0",
                Some("0001"),
            ),
            candidate(
                "IOService:/usb/ledger@01100000/IOUSBHostInterface@1",
                Some("0002"),
            ),
        ];
        assert!(
            sole_ledger(&adjacent_but_distinct).is_err(),
            "a differing serial is proof of two devices whatever the paths say"
        );
    }

    #[test]
    fn real_macos_paths_fail_closed_rather_than_guessing() {
        // Platform reports DevSrvsID:4294981010 and :4294981014 for one device.
        // They share only "DevSrvsID:" (10 of 20 bytes), below threshold, so
        // adjacency rule refuses rather than guesses. Only one passes
        // is_apdu_interface (interface 0, via interface-number, usage pages are
        // 0xffa0 and 0xf1d0, not 0xFF00).
        let one_device_two_interfaces = [
            candidate("DevSrvsID:4294981010", Some("0001")),
            candidate("DevSrvsID:4294981014", Some("0001")),
        ];
        let err = sole_ledger(&one_device_two_interfaces)
            .expect_err("this platform's paths carry no proof of a shared device");
        assert!(err.detail_string().contains("2 Ledger devices connected"));

        // The single candidate that actually reaches it on this hardware.
        let as_filtered = [candidate("DevSrvsID:4294981014", Some("0001"))];
        assert_eq!(sole_ledger(&as_filtered).unwrap(), 0);
    }

    #[test]
    fn several_interfaces_of_one_device_are_grouped_without_a_serial() {
        // No serial; path rule carries it with same threshold as select_ledger.
        // IOService:/… form works; see real_macos_paths for the form this
        // platform reports.
        let c = [
            candidate(
                "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0",
                None,
            ),
            candidate(
                "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@1",
                None,
            ),
        ];
        assert_eq!(sole_ledger(&c).unwrap(), 0);
    }

    #[test]
    fn two_attached_devices_are_refused_rather_than_picked_between() {
        // Equal serials on purpose: that is what real devices report, so path
        // rule must separate them.
        let c = [
            candidate("/dev/hidraw2", Some("0001")),
            candidate("/dev/hidraw3", Some("0001")),
        ];
        let err = sole_ledger(&c).expect_err("two devices must not resolve to one of them");
        let msg = err.detail_string();
        assert!(
            msg.contains("2 Ledger devices connected"),
            "the error must say why, got: {msg}"
        );
        assert!(
            msg.contains("host_device_path"),
            "and must name the remedy, got: {msg}"
        );
        assert!(
            !msg.contains("/dev/hidraw"),
            "host paths stay out of returned errors, got: {msg}"
        );
    }

    #[test]
    fn two_attached_devices_are_refused_without_serials_too() {
        // Distinct Linux hidraw nodes share only `/dev/`, which is far below
        // the sibling threshold, so they stay two devices.
        let c = [
            candidate("/dev/hidraw2", None),
            candidate("/dev/hidraw3", None),
        ];
        assert!(sole_ledger(&c).is_err());
    }

    #[test]
    fn an_empty_serial_is_not_evidence_of_anything() {
        // Empty serial must fall through to path rule, not match and fuse devices.
        let c = [
            candidate("/dev/hidraw2", Some("")),
            candidate("/dev/hidraw3", Some("")),
        ];
        assert!(
            sole_ledger(&c).is_err(),
            "an empty serial must fall through to the path rule, not match"
        );
    }

    #[test]
    fn nothing_attached_says_so_plainly() {
        let err = sole_ledger(&[]).expect_err("no devices is an error");
        assert!(err.detail_string().contains("no Ledger device found"));
    }

    #[test]
    fn two_devices_each_with_two_interfaces_are_two_devices() {
        // Grouping must survive interleaved enumeration order.
        let c = [
            candidate(
                "IOService:/usb/ledger@01100000/IOUSBHostInterface@0",
                Some("0001"),
            ),
            candidate(
                "IOService:/usb/ledger@01200000/IOUSBHostInterface@0",
                Some("0002"),
            ),
            candidate(
                "IOService:/usb/ledger@01100000/IOUSBHostInterface@1",
                Some("0001"),
            ),
            candidate(
                "IOService:/usb/ledger@01200000/IOUSBHostInterface@1",
                Some("0002"),
            ),
        ];
        let err = sole_ledger(&c).expect_err("still two devices");
        let msg = err.detail_string();
        assert!(
            msg.contains("2 Ledger devices connected"),
            "the count must be devices, not interfaces: {msg}"
        );
    }

    #[test]
    fn sibling_grouping_is_symmetric() {
        // `select_ledger` compares every candidate against one requested path,
        // so its ratio has a fixed denominator. `sole_ledger` compares
        // candidates against each other, where a long path next to a short one
        // must not read as a sibling just because the comparison ran one way.
        let long = "IOService:/AppleT8103/usb-drd0/ledger@01100000/IOUSBHostInterface@0";
        let short = "IOService:/A";
        assert_eq!(
            is_sibling_interface(long, short),
            is_sibling_interface(short, long)
        );
        assert!(!is_sibling_interface(long, short));
    }

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
