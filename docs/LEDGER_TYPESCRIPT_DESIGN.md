# Design: Ledger signing for the TypeScript keychain

Status: **proposal, no code written.** This is the design we offered
@dev-jodee and @amilz, and the shape of the PR that would follow. It is the
browser path Pay.sh actually needs, which the Rust backend does not serve.

## Why this is not a port of the Rust backend

The Rust backend drives `solana-remote-wallet`, which owns its own `hidapi`
handle and speaks Solana-app APDUs directly. None of that crosses to TypeScript:
there is no `hidapi` in a browser, and the transport a browser can use
(`navigator.hid`) is a different API with a different permission model from
Node's.

Ledger already solved this. The **Device Management Kit** (DMK) is their
supported TypeScript stack, and its central design decision is exactly the one
we need: the core is transport-agnostic, and a transport is injected. So the
right shape is not "a Ledger signer" but "a transport-injected core plus two
thin entry points".

## Package layout

Three packages, mapping onto the existing convention (`typescript/packages/*`,
each publishing `@solana/keychain-<backend>`, `sideEffects: false`, ESM-only,
`exports` map with `types` + `import`).

| Package | Contains | Depends on |
|---|---|---|
| `@solana/keychain-ledger-core` | The signer. All APDU/envelope logic. Takes a transport as a constructor argument and never imports one. | `@solana/keychain-core`, DMK core |
| `@solana/keychain-ledger-node` | `createLedgerNodeSigner()`. Constructs the Node HID transport and hands it to core. | ledger-core, DMK Node HID transport |
| `@solana/keychain-ledger-web` | `createLedgerWebSigner()`. Constructs the WebHID transport and hands it to core. | ledger-core, DMK WebHID transport |

**The split is the whole point, and it is a bundling constraint, not taste.**
`node-hid` is a native module. If a browser bundler can reach it through any
import path, from any conditional, the build breaks or silently pulls a
polyfill. One package with a runtime `if (typeof window)` branch does not work,
because bundlers resolve imports statically. Two entry points that never import
each other is the only arrangement that holds.

Consequences to enforce in review:

- `ledger-core` must have **zero** transport imports, including type-only ones
  that resolve to a transport package. Types come from DMK's transport
  interface, not from a concrete transport.
- `ledger-node` must never be reachable from `ledger-web`'s dependency graph.
- The umbrella `@solana/keychain` must re-export **only** `ledger-core` types
  and `ledger-web`, or neither. Adding `ledger-node` to the umbrella puts
  `node-hid` into every browser consumer of the umbrella, which is the failure
  this layout exists to prevent.

That last point interacts with an existing rule: adding a backend to the TS
umbrella touches it in seven places plus two workflows. For Ledger, the honest
answer may be **not to add it to the umbrella at all**, the way Crossmint is
excluded at the type level for a different reason. A hardware wallet is opt-in
by nature; nobody gets one by accident.

## Capability typing

The Rust side splits capabilities across traits and the TS side splits them
across interfaces in `@solana/keychain-core/types.ts`:
`SolanaTransactionSigner`, `SolanaModifyingSigner`, `SolanaSendingSigner`,
`SolanaMessageSigner`. Kit classifies signers by **duck-typed method presence**,
so a stub that throws misclassifies the signer.

A Ledger implements:

- `SolanaTransactionSigner` — signs and returns; it never broadcasts.
- `SolanaMessageSigner` — but see the envelope caveat below, which is a real
  semantic difference and not just a note.

It must expose **no** modifying or sending method at all, not a throwing one.

## The off-chain envelope is the trap

This is the part most likely to be got wrong, because it is wrong in a way that
type-checks and passes review.

`signMessage` on a Ledger does **not** sign the caller's bytes. The Solana app
parses a structured off-chain message and signs that envelope: 85 bytes of
header for a single signer under V0, comprising signing domain (16), version (1),
application domain (32), format (1), signer count (1), signers (32), and message
length (2, LE). The `@solana/kit` / `solana_offchain_message` layout is a
different, shorter header, and the device **rejects it outright**. The Rust
backend hit exactly this and it looked like a transport failure for months.

So `ledger-core` must:

1. Build the app's envelope itself, not reuse a generic off-chain serializer.
2. Export the envelope builder, because anything verifying a Ledger signature
   has to rebuild the same bytes; verifying against the raw payload always fails.
3. Refuse locally what the device would refuse: empty payloads, payloads over
   the length cap, and non-UTF-8. Non-printable-ASCII payloads go as format 1,
   which the device gates behind blind signing being enabled.

Port `rust/src/ledger/mod.rs`'s `ledger_offchain_envelope` byte for byte, and
port its conformance test against `LedgerHQ/app-solana` with it. That test is
what makes an upstream header change fail loudly instead of on someone's desk.

## Session and concurrency model

Carry over the Rust backend's hard-won behaviour rather than rediscovering it:

- **Verify before returning.** Every signature is checked with ed25519 against
  the pubkey cached at connect, over the exact bytes sent, and rejected rather
  than attached on mismatch. This is what makes a device swap fail closed.
- **A rejection is not a transport fault.** Do not tear down the session when
  the user declines; that bug made the Rust signer unusable after one decline.
- **Bound every operation.** Two tiers: seconds for exchanges that cannot
  involve the user, minutes for those that wait on a button press.
- **One confirmation at a time.** A second signing request while the device is
  mid-prompt should reject immediately with a distinguishable "busy" error
  rather than queue behind a human.

WebHID adds one thing Node does not have: `navigator.hid.requestDevice()` must
be called from a **user gesture**. So `ledger-web` cannot connect lazily on first
sign. The API has to expose an explicit `connect()` the app calls from a click
handler, and `createLedgerWebSigner` should take an already-granted
`HIDDevice`, or document the gesture requirement loudly. Getting this wrong
produces a signer that works in dev and fails in production behind a
`NotAllowedError`.

## Test strategy with no hardware in CI

Four layers. Only the last needs a device, and it never runs in CI.

**1. Pure-function tests.** The envelope builder, format selection, length caps,
and capability classification are all pure. These carry the same golden vectors
as the Rust side, which is also how cross-language parity is checked: the same
payload must produce byte-identical envelopes in both languages, and that is a
real test rather than an aspiration.

**2. A fake transport.** DMK's injected-transport design is what makes this
possible, and it is the main argument for building on DMK rather than on raw
WebHID. A `FakeTransport` implementing the transport interface returns canned
APDU responses, so the whole signer is testable in-process:

- a normal sign, asserting the APDU bytes sent are exactly right;
- `0x6985` (user cancel), asserting it maps to a rejection **and that the
  session survives**;
- a corrupted signature, asserting it is rejected rather than returned;
- a signature from the wrong key, asserting the device-swap case fails closed;
- a transport that never resolves, asserting the timeout fires and a concurrent
  request gets the busy error rather than hanging.

Every one of those is a bug found on the Rust side, and every one is reachable
without hardware.

**3. Bundling assertions, in CI.** These are the ones people forget, and they
are cheap:

- Build a browser bundle importing `ledger-web` and assert `node-hid` and
  `node:*` builtins appear nowhere in the output.
- Extend `test-treeshake-umbrella.mjs` so a consumer importing one unrelated
  backend does not pull any Ledger code.
- Assert `ledger-core` has no dependency on either transport package.

**4. A hardware runbook, run by a human.** Mirroring
`scripts/ledger-hardware-runbook.sh`: locked device, another app holding it,
app closed, unplug/replug, reject-then-sign-again, and blind signing for
non-ASCII messages, plus the two browser-specific cases Node cannot show —
permission denied at `requestDevice`, and the device revoked mid-session. It
writes a transcript to attach to the PR. Browser results need one run per
engine, since WebHID support differs across Chromium, and Safari and Firefox do
not implement it at all, which the README must say plainly.

## What to confirm before writing code

Three things I have not verified and would check first rather than design
around:

1. Which DMK package provides the Solana app's APDUs, and whether it already
   implements off-chain message signing or only transaction signing. If it does
   the envelope for us, most of the trap above disappears; if it does not, we
   own it.
2. Whether DMK's WebHID transport handles the Ledger re-enumerating after an app
   launch, which is the event that makes the Rust backend retry for five
   seconds. In a browser, re-enumeration may drop the permission grant entirely.
3. Whether Pay.sh needs `signMessage` at all in the browser, or only
   `signTransaction`. If only the latter, the envelope work is out of scope for
   v1 and the surface shrinks a great deal.
