# Leftovers

Follow-up work left behind by the fixes on branch `fix/crossmint-create-transaction-id` (PR #299). Each item names the code it concerns and why it was not done, so the next pass can decide rather than re-derive.

## Left open

### The fork live workflow's split is unverified end to end

The post-marker work now runs in its own job with no provider credentials, so
the credentialed job holds read scopes only. Workflow changes have no test
harness in this repo: this was verified by reading the yml and with
`actionlint`. The manual dispatch path still needs one run against a real fork
pull request.

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

### No lookup-by-key call exists

An ambiguous create now reports the idempotency key (Fireblocks PROGRAM_CALL
reports its `externalTxId`), so a byte-identical resend is safe and the request
is findable. Nothing in this library looks a transaction up by that key:
reconciling still means calling the provider yourself.

### Fee payer of provider-rewritten output is not recomputed

The scanner asked for the fee payer to be recomputed from the returned wire
bytes of a Fordefi rewrite. That was refused. The returned signature is already
resolved by address and ed25519-verified, and requiring the vault to be the fee
payer of provider-rewritten output risks rejecting valid rewrites callers are
documented to continue from.
