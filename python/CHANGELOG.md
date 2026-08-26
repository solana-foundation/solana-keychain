## 2.0.0b1 - 2026-08-26

First beta, and the first published version of the Python package. The version
number tracks the other language implementations rather than the package's own
history. Installing it needs an explicit pin or `pip install --pre`.

### Features

- initial Python implementation: `SolanaSigner` base contract with the `TransactionSigner` / `ModifyingSigner` / `SendingSigner` capability classes, redacting `SignerError`, transaction utilities, and golden wire-format vectors (#205)
- remote signer core — `fetch_signer_json` error pipeline, HTTPS enforcement, response sanitization — plus the Vault backend (#208)
- thirteen-backend parity: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila (#210, #211, #213–#221)
- `create_keychain_signer()` umbrella factory with lazy per-backend imports, plus the env-gated live integration suite (#222)
- Fordefi backend: `FordefiBlackBoxSigner` for raw signing and `FordefiNativeAutoSigner` for native Solana auto-broadcast, pluggable P-256 request signer, vault ownership verification (#227)
- `SignedTransaction.transaction`: the authoritative signed transaction, so callers never have to know whether a backend signed the object they passed in
- `sign_and_send_transaction()`: one call to get a transaction on chain, using the provider's broadcast for a `SendingSigner` and a caller-injected send function for a `TransactionSigner` or `ModifyingSigner`
- `FordefiNativeManualSigner`: Fordefi's `push_mode: manual` as a `ModifyingSigner`, where Fordefi rewrites the blockhash and Compute Budget fee instructions and signs without broadcasting; the vault must be the fee payer of an as-yet-unsigned transaction, the returned signature is verified against the rewritten message at the vault's signer position, and the rewritten transaction comes back as `SignedTransaction.transaction`
- `BROADCAST_UNCONFIRMED` error code and `provider_may_have_accepted()`, so a failure after a provider accepted a transaction is distinguishable from one before (#269)
- Crossmint is sending-only: `sign_transaction` fails and `sign_and_send_transaction` returns the signature of the landed transaction without mutating the caller's transaction (#284)
- trusted-provider model with consolidated response handling and shared helpers across backends (#274, #281)

### Bug Fixes

- verify versioned-message signatures against `0x80`-prefixed bytes, which `solders` omits from `bytes(message)` (#222)
- scope the integration require-run guard to the requested flow so a configured backend cannot mask a skipped one (#222)
- Fireblocks no longer waits one extra poll interval before reporting a polling timeout
