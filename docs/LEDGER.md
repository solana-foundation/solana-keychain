# Ledger backend

The only backend that drives hardware on the local machine. Everything else in
this crate talks to a remote HTTP API; this one speaks APDUs over USB-HID
through [`solana-remote-wallet`](https://docs.rs/solana-remote-wallet). The
private key never leaves the device and every signature is confirmed on its
screen.

```rust
use solana_keychain::{LedgerConfig, LedgerSigner};

// Interactive default: sole attached device, DEFAULT_SIGN_TIMEOUT for signing,
// auto-launches the Solana app if it is not already open.
let signer = LedgerSigner::connect(None, false, None)?;

// Unattended: never poke the device on our own initiative, fail faster.
let signer = LedgerSigner::connect_with(LedgerConfig {
    auto_open_app: false,
    signing_timeout: std::time::Duration::from_secs(60),
    ..LedgerConfig::default()
})?;
```

## Timeouts

Every device command is bounded, in two tiers, because a Ledger legitimately
blocks while the user reads a confirm screen.

| Tier | Commands | Default |
|---|---|---|
| Fast | enumeration, unconfirmed pubkey read, `is_available`, `is_attached` | `OPS_TIMEOUT` |
| Interactive | `sign_transaction`, `sign_message`, connect with `confirm_pubkey_on_device` or `auto_open_app` | `LedgerConfig::signing_timeout`, defaults to `DEFAULT_SIGN_TIMEOUT` |

Both defaults are named constants rather than numbers repeated here. This
document used to restate them in prose, and kept the old figures after
`DEFAULT_SIGN_TIMEOUT` was retuned downwards, so a reader trusting it would have
had a confirmation time out minutes earlier than promised.
`docs_quote_the_real_timeout_constants` now fails if the prose and the code drift
apart again.

Two minutes is long enough for a deliberate read-and-approve and short enough
that an abandoned prompt does not hold the device for the rest of the process's
life.

**Why a timeout alone is not the whole story.** The device thread is a single
serialized actor, and the read it blocks in has no timeout of its own:
`solana-remote-wallet`'s `Ledger::read` calls `hidapi`'s blocking
`HidDevice::read`, which nothing on the host can interrupt. Returning control to
one caller therefore leaves the actor stuck, and without more, every later
command would queue behind a human who may never press the button and burn its
own full timeout in turn.

So the device is **claimed**, not merely checked. Anything that touches it takes
an exclusive claim with a single `compare_exchange` *before* the command is
enqueued, and releases it on drop. Exactly one of any number of racing callers
wins; the rest get "Ledger is busy with another operation or awaiting on-device
confirmation" in milliseconds. One process therefore serializes to one on-device
confirmation at a time, by construction rather than by timing.

## `auto_open_app` and its device side effect

When a connect fails because the Solana app is not running, the backend talks to
the BOLOS dashboard and launches it: `getAppAndVersion`, then `openApp`, quitting
a different app first if one is open.

**This writes APDUs to a security device without asking the host user**, and on
most firmware the device then shows its own confirmation prompt. It defaults to
`true` because for an interactive CLI the alternative is telling the user to go
and hand-navigate the device. Set `auto_open_app: false` for unattended or
server-side use; connect then fails with the underlying "open the Solana app"
error. A decline on the device is reported as `SignerError::UserRejected` either
way. The PIN can never be entered or bypassed from the host: that is a hardware
invariant, not a policy choice here.

## Linux: udev rules

On Linux a Ledger is invisible to a non-root process until udev grants your user
access to the device node. Without the rules, enumeration finds nothing and the
failure looks identical to an unplugged cable.

The canonical rules come from
[`LedgerHQ/udev-rules`](https://github.com/LedgerHQ/udev-rules):

**Write the file yourself. Do not pipe a script into a root shell.** Ledger's
README suggests
`wget -q -O - .../master/add_udev_rules.sh | sudo bash`, and this documentation
used to repeat it. That fetches a *mutable branch* and hands the response to
`sudo bash`: whoever controls that branch, that repository or that download path
at the moment you run it gets root on your machine. The content is nine lines of
static udev rules. There is no reason to execute it at all.

The rules, verbatim, as of `LedgerHQ/udev-rules` commit
[`6d9b0257`](https://github.com/LedgerHQ/udev-rules/commit/6d9b02572ce3ba3cddcbabdb6f625a8cf333e592):

```
# HW.1, Nano
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2581", ATTRS{idProduct}=="1b7c|2b7c|3b7c|4b7c", TAG+="uaccess", TAG+="udev-acl"

# Blue, NanoS, Aramis, HW.2, Nano X, NanoSP, Stax, Ledger Test,
SUBSYSTEMS=="usb", ATTRS{idVendor}=="2c97", TAG+="uaccess", TAG+="udev-acl"

# Same, but with hidraw-based library (instead of libusb)
KERNEL=="hidraw*", ATTRS{idVendor}=="2c97", MODE="0666"
```

Save that as `/etc/udev/rules.d/20-hw1.rules`, then reload:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

If you would rather fetch it than paste it, pin the revision and check the
digest **before** it goes anywhere near `sudo`:

```bash
curl -fsSLO https://raw.githubusercontent.com/LedgerHQ/udev-rules/6d9b0257/20-hw1.rules
echo "0a67fa9b7024048f7f967fef8d33c2da38dae9354e996c131b79a014f62b7efc  20-hw1.rules" | shasum -a 256 -c
# only if that prints OK:
sudo install -m 0644 20-hw1.rules /etc/udev/rules.d/20-hw1.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Read the file before installing it either way. It is short, and it is granting
device access on your machine.

Two things worth knowing:

- **The third rule is the one this backend depends on.** We reach the device
  through `hidapi`, which uses `hidraw` on Linux. Rules that grant only the
  `usb` subsystem are not enough.
- **No group membership is required.** The modern rules use `TAG+="uaccess"`,
  which grants access to the user on the active seat. The older `plugdev`-group
  approach is not what Ledger ships today, so adding yourself to `plugdev` is
  neither necessary nor sufficient. If you are on a headless box, over SSH, or
  in a container, `uaccess` does not apply because there is no local seat: that
  is the case where you need an explicit `MODE`/`GROUP` rule of your own.

After installing, unplug and replug the device.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `NotAvailable` mentioning udev, on Linux | Rules not installed, or installed but not reloaded | Install the rules above, then replug |
| `NotAvailable` naming a product id and a `solana-remote-wallet` version | Device model newer than the resolved `solana-remote-wallet` | See the table below |
| `NotAvailable`: "either locked, or another application is holding the device" | Device auto-locked, **or** Ledger Live has the handle | Unlock and open the Solana app; quit Ledger Live |
| `NotAvailable`: "busy with another operation or awaiting on-device confirmation" | Another caller holds the device, or a prompt is unanswered | Answer or dismiss it on the device, or wait |
| `NotAvailable` listing several devices | More than one Ledger attached | Pass `host_device_path` |
| `UserRejected` | Declined on the device screen | Retry and approve |

## Device support by resolved `solana-remote-wallet`

`solana-remote-wallet` selects devices by a per-model USB product-id allowlist.
A model it predates is not rejected with an explanation, it simply never
enumerates, so every layer above reports "no Ledger device found" while you are
holding one that is plugged in, unlocked and running the app. This is the most
misleading failure this backend can produce, and which version you get is a
property of the **consumer's** dependency graph, not of this crate.

Verified by reading the vendored sources of both versions:

| Model | `4.0.x` | `>= 4.1` |
|---|---|---|
| Nano S | yes | yes |
| Nano X | yes | yes |
| Nano S Plus | yes | yes |
| Stax | yes | yes |
| Flex | yes | yes |
| **Nano Gen5** | **no** | yes |

`4.0.3` defines PID lists for Nano S / X / S Plus / Stax / Flex only; `4.2.2`
adds `LEDGER_NANO_GEN5_PIDS`. This crate resolves `4.2.2`, so a Gen5 works here.
A consumer pinned to the Solana 3.x crate line resolves `4.0.x` and cannot see a
Gen5 at all.

The backend guards against the silent case: if `hidapi` reports an attached
Ledger-vendor device that `solana-remote-wallet` did not enumerate, the error
names the product id and the version requirement instead of blaming the cable.
Check what you resolved with:

```bash
just rust-which-remote-wallet
```

## Off-chain message signing

`sign_message` does **not** raw-sign the bytes you pass. A hardware wallet
cannot. The payload is wrapped in the app's off-chain-message envelope and the
device signs the envelope, so `signature.verify(pubkey, message)` over your
payload will fail. Rebuild the bytes with `ledger_offchain_envelope` to verify.

The envelope is deliberately not what `solana_offchain_message` produces: that
crate emits a 20-byte header, the app parses an 85-byte one for V0, and the
crate's output is rejected by the device. `just rust-test-ledger-conformance`
checks our layout against `LedgerHQ/app-solana`'s own source at a pinned commit,
so an upstream header change fails loudly rather than silently on hardware.

The app also documents a V1 layout (sRFC 38) that drops the application domain
and the length prefix and requires sorted unique signers. We emit V0, which it
still parses; adopting V1 would be a real envelope change.

## Testing

| Command | Needs a device | What it covers |
|---|---|---|
| `just rust-test` | no | Full matrix including the backend's unit tests |
| `just rust-test-ledger` | optional | Hardware suite; skips cleanly when nothing is attached |
| `just rust-test-ledger-conformance` | no (network) | Envelope layout against upstream app source |
| `just rust-ledger-open-app` | yes | Dashboard auto-launch by hand |

The hardware suite skips only when **no device is attached**. If one is attached
and unusable (locked, wrong app, held by another process) it fails, because
reporting that as a pass is how a locked device once made the whole suite look
green while testing nothing.
