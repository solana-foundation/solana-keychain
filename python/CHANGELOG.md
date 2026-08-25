## Unreleased

### Features

- initial Python implementation: `SolanaSigner` contract, redacting `SignerError`, transaction utilities, and golden wire-format vectors (#205)
- remote signer core — `fetch_signer_json` error pipeline, HTTPS enforcement, response sanitization — plus the Vault backend (#208)
- thirteen-backend parity: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila (#210, #211, #213–#221)
- `create_keychain_signer()` umbrella factory with lazy per-backend imports, plus the env-gated live integration suite (#222)
- Fordefi backend: black-box raw signing and native Solana auto-broadcast mode, pluggable P-256 request signer, vault ownership verification (#227)
- Fordefi native manual mode: provider-modified signing with caller-managed broadcasting and authoritative returned transactions

### Bug Fixes

- verify versioned-message signatures against `0x80`-prefixed bytes, which `solders` omits from `bytes(message)` (#222)
- scope the integration require-run guard to the requested flow so a configured backend cannot mask a skipped one (#222)
- Fireblocks no longer waits one extra poll interval before reporting a polling timeout
