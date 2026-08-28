# Leftovers

Follow-up work left behind by the fixes on branch `fix/crossmint-create-transaction-id` (PR #299). Each item names the code it concerns and why it was not done, so the next pass can decide rather than re-derive.

## Left open by fixes on this branch

### `pending_transaction_id` is accepted by Fordefi modes that ignore it

`pending_transaction_id` sits on the shared `FordefiSignerConfig` (`python/src/solana_keychain/fordefi/signer.py`), so `FordefiBlackBoxSigner` and `FordefiNativeManualSigner` accept it and silently ignore it. Only native auto writes to it.

Every other mode-mismatched config field is rejected at construction (`chain`, `push_mode`, `fee`). This one is not, so it is an inconsistency in the config contract. Decide: reject it in the two constructors that cannot use it, or document that it is native-auto only.

### The 408 fix does not add a reconciliation path

Commit `7f2c1db` reclassifies a 408 create as `BROADCAST_UNCONFIRMED` in all four
languages. It does not surface the idempotence key in the error, and no lookup-by-key
call exists, so recovery still means listing the provider's recent transactions by
hand.

### The fork live workflow keeps its broad write scopes

Commit `092f234` stops the fork branch name from being parsed as JavaScript. The
post-marker step still runs in the same job as the Doppler secret injection and still
holds `issues: write`, `pull-requests: write` and `actions: write`. Splitting the
comment-and-rerun work into a separate job with narrower permissions would remove the
secret-adjacency entirely. Not done: it changes the workflow's shape, and the manual
dispatch flow would need re-testing on a real fork pull request.

Workflow changes have no test harness in this repo. Both commits' workflow edits were
verified by reading the yml only.

### Rust cannot report a pending request id outside a broadcast error

Commit `45eb7a2` attaches the Fordefi transaction id to a poll timeout in
TypeScript, Python and Go. Rust is unchanged: `SignerError::RemoteApiError`
renders nothing of its payload (`Display` is the bare "Remote API error" and
`Debug` is redacted), and `BroadcastUnconfirmed` is the only variant with a
`provider_tx_id` field. Reporting a Fordefi manual-mode timeout as an
unconfirmed broadcast would be false, since manual mode never broadcasts, so
there is nowhere for the id to go.

Closing this means either a `provider_tx_id` on more variants or a separate
"pending request" variant. Both are error-type changes with callers matching
on codes, so neither was done here.

### The auto-mode pre-signed guard cannot tell unsent from already-broadcast

Native auto refuses a transaction that already carries a signature, because
it broadcasts and its blockhash rewrite would land the same transfer twice.
A signature is evidence Fordefi signed those bytes once, not proof they were
broadcast, so a caller who had them signed through black box mode and never
sent them cannot hand them to auto. Nothing in this repo does that, and the
safe reading is the one that refuses.

Manual mode no longer carries this check: it never broadcasts, so what a
caller submits is their call. Crossmint's sending path has no such
precondition either, and whether it should was raised and not decided.

### The TS message decode is now on the guard path

Commit `8d7d3ac` decodes `transaction.messageBytes` inside both native
guards, so a message that will not decode fails as `PARSING_ERROR` before
any request. The decode takes a copy of the bytes, because a
`SharedArrayBuffer`-backed view at a non-zero offset is mis-sliced by the
codecs. That is the second place in this package copying bytes to work
around that codec defect, alongside the two native submit sites; a shared
normalizer would cover all of them.

Not done: the scanner also asked for the fee payer to be recomputed from
the returned wire bytes. That was refused. The returned signature is
already resolved by address and ed25519-verified, and requiring the vault
to be the fee payer of provider-rewritten output risks rejecting valid
rewrites callers are documented to continue from.

## Carried in from earlier work on this branch

- **Fireblocks creates carry no external transaction id.** No `externalTxId` (TS/Go) or `external_tx_id` (Rust/Python) is sent, so an ambiguous create has no lookup key and a rebuilt retry is a new transaction. Deferred from the fix in `f039ae5`, which only reports the ambiguity.
- **`docs/ADDING_SIGNERS.md:695`** says never rewrap an abort as a signer error. Crossmint and Fireblocks both deliberately do exactly that, so the rule and the code disagree. Amend one.
- **No caller-facing note on abort semantics in TS.** Nothing tells callers that `abortSignal` cannot recall work the provider already accepted, or that Kit re-checks the signal after the signer returns, which can discard a landed signature at the call site.

## Test coverage gaps

- `PendingTransactionId` clear-on-normal-return is tested for Crossmint (`test_a_completed_send_leaves_no_id_in_the_pending_slot`) but not for Fordefi, where only the cancellation case is covered. A stale id left in the slot after a successful send would send a caller reconciling a transaction they already hold the signature for.
