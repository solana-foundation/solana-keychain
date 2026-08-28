# Leftovers

Follow-up work left behind by the fixes on branch `fix/crossmint-create-transaction-id` (PR #299). Each item names the code it concerns and why it was not done, so the next pass can decide rather than re-derive.

## Left open by fixes on this branch

### The upstream base64 codec bug is unfixed

Commit `a288975` normalizes `transaction.messageBytes` into a fresh `Uint8Array` at the two Fordefi native submit sites (`typescript/packages/fordefi/src/fordefi-signer.ts`, native manual and native auto). The underlying defect is in `@solana/codecs-core@8.0.0` `toArrayBuffer`: for a `SharedArrayBuffer`-backed view it copies into a fresh buffer sized `bytes.length` but still slices at `bytes.byteOffset`, so a view at offset N encodes as the message tail shifted by N.

Consequences of fixing only the call sites:

- Any other consumer of that codec in the dependency tree that passes a caller-supplied view stays exposed.
- A new call site in this repo can reintroduce the bug silently.

Options: a shared `normalizeMessageBytes` helper in `@solana/keychain-core` that every backend uses, a lint rule banning a raw `messageBytes` argument to a codec, or an upstream fix. None applied.

### The Python pending-id slot is opt-in

Commit `564f2b6` adds `PendingTransactionId` (`python/src/solana_keychain/core/transaction_util.py`) and wires it into the Crossmint and Fordefi native-auto sends. A caller who never registers a slot still recovers the accepted provider transaction id only from the WARNING log line, because a cancellation must be re-raised as `asyncio.CancelledError` and awaiting a cancelled task discards the raised message.

No default slot is provided, and none can be: a per-signer default would race between concurrent `sign_and_send_transaction` calls on the same signer.

### `pending_transaction_id` is accepted by Fordefi modes that ignore it

`pending_transaction_id` sits on the shared `FordefiSignerConfig` (`python/src/solana_keychain/fordefi/signer.py`), so `FordefiBlackBoxSigner` and `FordefiNativeManualSigner` accept it and silently ignore it. Only native auto writes to it.

Every other mode-mismatched config field is rejected at construction (`chain`, `push_mode`, `fee`). This one is not, so it is an inconsistency in the config contract. Decide: reject it in the two constructors that cannot use it, or document that it is native-auto only.

### An id-less accepted create still cannot be reconciled

Commit `43c8fd1` makes Rust, TypeScript and Python reject an empty-string transaction id on create, matching Go. That removes a fake id from the unconfirmed error, but it does not give the caller a lookup handle.

Recovery still rests entirely on the message-derived idempotency key, so:

- A byte-identical resend is safe: the provider deduplicates the create.
- A rebuilt transaction (fresh blockhash) derives a different key and executes as a genuine second transfer.

Fordefi exposes no lookup-by-idempotency-key endpoint, so this is a provider API gap, not something the SDK can close. Already stated in the security model; listed here so it is not rediscovered as a defect.

### A whitespace-only create id still passes

`rust/src/fordefi/mod.rs` rejects `""` but not `" "`, and the TypeScript, Python and Go
checks are equally length-based. A whitespace id would be used verbatim as the poll
URL segment. Trimming before the emptiness check would close it; no provider is known
to behave this way, so it was left alone.

### The 408 fix does not add a reconciliation path

Commit `7f2c1db` reclassifies a 408 create as `BROADCAST_UNCONFIRMED` in all four
languages. It does not surface the idempotence key in the error, and no lookup-by-key
call exists, so recovery still means listing the provider's recent transactions by
hand. Same provider API gap as the id-less accepted create above.

### The fork live workflow keeps its broad write scopes

Commit `092f234` stops the fork branch name from being parsed as JavaScript. The
post-marker step still runs in the same job as the Doppler secret injection and still
holds `issues: write`, `pull-requests: write` and `actions: write`. Splitting the
comment-and-rerun work into a separate job with narrower permissions would remove the
secret-adjacency entirely. Not done: it changes the workflow's shape, and the manual
dispatch flow would need re-testing on a real fork pull request.

Workflow changes have no test harness in this repo. Both commits' workflow edits were
verified by reading the yml only.

### Provider identifiers are still only escaped, never validated

Commit `157b16f` percent-encodes the Openfort account id and the Privy and Para
wallet ids as single path segments, matching what TypeScript and Python already
did. No grammar check was added: an `acc_<uuid>` regex would reject sandbox and
test ids, and once the id is one opaque segment it buys nothing. Escaping cannot
stop a caller from deliberately configuring the wrong account, and it does not
help an application whose account allowlist uses prefix matching instead of
equality. Multi-tenant account selection stays an application concern.

Not swept: whether any other backend interpolates a configured identifier into a
URL without the shared encoder.

### The Utila vault check cannot cover a bare leaf wallet id

Commit `5c8822e` rejects a `vaults/{v}/wallets/{w}` wallet id whose parent vault
differs from the configured `vault_id`. When the wallet id is a bare leaf there
is no parent to compare against, so a colliding leaf under the wrong vault still
resolves silently. Callers needing that guarantee must assert the signer's
resolved address against an expected one.

Also unverified: whether Utila leaf wallet ids are actually vault-scoped rather
than globally unique. The whole concern rests on that assumption, and only the
mocks in this repo assert the canonical resource shape.

### The recovered create id depends on the provider's error body

Commit `908f1cf` keeps a top-level `id` from a non-2xx create body, in TypeScript
and Python. It cannot invent one: a dropped connection or an unread body carries
no id, and recovery there still rests on the message-derived idempotency key. The
field is populated for every backend that goes through the core HTTP helper, so a
provider whose error bodies use `id` for something other than a transaction
handle would surface a misleading value.

Rust and Go read the id from a 5xx body already; that half predates this branch.

### Changing the Crossmint idempotency key opens a one-deploy dedup gap

Commit `e1a12a4` binds the key to the signer locator, so the same message bytes
now derive a different key than they did before. A create that an earlier
version left in flight (accepted but unconfirmed) is no longer deduplicated by a
byte-identical resend from this version: Crossmint sees an unfamiliar key and
creates a second operation.

The window is one deploy wide and only touches already-ambiguous creates, so no
mitigation was added. If this ever ships to consumers with outstanding
unconfirmed creates, the operational fix is to reconcile those before upgrading.

### Nothing pins the idempotency key across languages

Each language has a test asserting the exact prefix bytes
(`crossmint:solana:0::MSG`), which catches a drifting format in review. There is
still no shared golden vector: four independently correct-looking
implementations could diverge on a case none of the four tests covers (a
non-ASCII locator, for instance, where the length is counted in UTF-8 bytes in
all four but nothing proves it).

### Crossmint signature verification only proves the envelope is self-consistent

Commit `285dbed` ed25519-verifies the returned slot-0 signature against the
returned message. It cannot detect a provider that reports `success` for a
transaction that never landed, and it does nothing when Crossmint returns only
`onChain.txId`, which is accepted as an opaque base58 signature with nothing to
verify against. Both remain trusted-provider assumptions.

This reversed the stance of #284, which treated the returned value as trusted
because it is never attached to the caller's transaction. If that reasoning is
ever revisited, the check is a single call per language.

### No Crossmint test covers a v0 or v1 returned envelope outside Python

Commit `fb505e8` removed Python's version narrowing and covers v1 with a test.
Rust, Go and TypeScript were already version-agnostic, but every Crossmint test
in those three uses a legacy transaction, so the version-prefix handling inside
the signature verification is exercised only by Fordefi's tests, not Crossmint's.

## Release, not code

The hardened Crossmint managed flow (message-derived idempotency key, provider transaction id preserved on ambiguous failures, no direct-signing surface) exists only on `@solana/keychain-crossmint@2.0.0-beta.1`. The `latest` dist-tag is still `1.4.0`, which has none of it.

Consumers are on the unhardened code regardless of this repo's state. Either ship the hardening on a `1.4.x` line or promote `2.0.0` out of beta. Release owner's call.

## Carried in from earlier work on this branch

- **Fireblocks creates carry no external transaction id.** No `externalTxId` (TS/Go) or `external_tx_id` (Rust/Python) is sent, so an ambiguous create has no lookup key and a rebuilt retry is a new transaction. Deferred from the fix in `f039ae5`, which only reports the ambiguity.
- **`typescript/packages/core/src/batch.ts:43-51`** (Fordefi native auto) uses `Promise.all`, so sibling submissions stay in flight after one rejects. Untouched; needs its own decision about whether a rejection should cancel the rest.
- **5xx id recovery is uneven across languages.** Rust and Go can read a provider transaction id out of a 5xx body; TS and Python cannot, because `fetchSignerJson` / `fetch_signer_json` consume the body before the caller sees it.
- **`docs/ADDING_SIGNERS.md:695`** says never rewrap an abort as a signer error. Crossmint and Fireblocks both deliberately do exactly that, so the rule and the code disagree. Amend one.
- **No caller-facing note on abort semantics in TS.** Nothing tells callers that `abortSignal` cannot recall work the provider already accepted, or that Kit re-checks the signal after the signer returns, which can discard a landed signature at the call site.

## Test coverage gaps

- The offset-view tests added in `a288975` cover the two Fordefi native submit sites only. Whether any other backend decodes caller-supplied `messageBytes` through the same codec was not audited.
- `PendingTransactionId` clear-on-normal-return is tested for Crossmint (`test_a_completed_send_leaves_no_id_in_the_pending_slot`) but not for Fordefi, where only the cancellation case is covered. A stale id left in the slot after a successful send would send a caller reconciling a transaction they already hold the signature for.
