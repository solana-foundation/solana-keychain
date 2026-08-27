# CLAUDE.md

One `SolanaSigner` contract over 14 backends in Rust, TypeScript, Python and Go, kept at cross-language parity. Adding a backend: [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md).

## Commands

Always use `just`, never raw `cargo`/`pnpm`/`pytest`/`go test`: the recipes encode flags those get wrong.

- `just rust-test` runs the `sdk-v2`, `sdk-v3` and `sdk-v4` matrices. `cargo test --all-features` fails: the SDK features are mutually exclusive.
- `just ts-treeshake` after touching TS exports; every package and the umbrella must stay tree-shakable.
- Integration recipes spawn their own local `vault server -dev` and load `.env`. Never start Vault or pass secrets yourself.
- Releasing: check version consistency across **all** crates and packages.

## Security standing

Consumer-facing summary in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md); keep it in sync when a change alters the signing or sending shapes. Keychain is a signing adapter. It validates the signing hop, not the caller's intent: no simulation, no transaction-content checks, no policy engine, no key custody.

- **Signature binding.** A provider-returned signature is verified with ed25519 against locally computed message bytes at the signer's required position. Mismatch fails; it is never attached.
- **Trusted-provider model.** Where a provider rewrites the transaction (Crossmint gas sponsorship, Fordefi native mode), the returned signature covers *its* bytes, not the caller's, and is not diffable. Crossmint's `SignerSecret` auto-approval delegates the choice of what gets approved to Crossmint.
- **Broadcast-managed signers** (Crossmint, Fordefi native mode) never mutate the caller's transaction, and a failure does not mean nothing landed. `BROADCAST_UNCONFIRMED` carries a provider transaction id only when the create was accepted; without one, recovery rests on the message-derived idempotency key, which makes a byte-identical resend safe and a rebuilt transaction a new transfer.
- **Redacted errors.** `SignerError` messages, `Debug`/`repr`, and sanitized remote bodies must never carry key material or raw provider responses. Callers match stable codes.
- **Redirects always rejected**, timeouts always set, HTTPS enforced on configured base URLs. Two carve-outs: Vault allows plain-HTTP loopback for `vault server -dev`, and the KMS backends use their vendor SDK's transport. Signing before `init()` fails rather than using the zero address.
- **Pinned wire format.** Golden vectors freeze the serialized bytes; never regenerate them to make a suite pass.
- Rust zeroizes intermediate key buffers. Go and Python cannot: treat the whole process memory as sensitive with local-key backends.
- Audit coverage is uneven across the four languages and moves every release. [audits/AUDIT_STATUS.md](audits/AUDIT_STATUS.md) is the source of truth.

## Cross-language gotchas

- **`init()` before use** for Privy, Fireblocks, Dfns, Crossmint, Para, Openfort. The `Signer::from_*` (Rust) and `await createXSigner(...)` / `create_keychain_signer(...)` factories do it for you; direct construction skips it.
- **Capability is in the type, and the umbrella hides it.** A backend implements exactly one of the transaction, modifying or sending capability traits. The Rust umbrella `Signer` enum implements only the base trait: capabilities are reached through `as_transaction_signer()` / `as_sending_signer()`, which return `None` when absent, or through its own variant-routing `sign_and_send`. In TS, narrow with the `isSolana*Signer` guards; `SolanaMessageSigner` is orthogonal. Fordefi is two types (`FordefiBlackBoxSigner`, `FordefiNativeAutoSigner`), picked by `config.chain`.
- **Go capability is by type assertion**, so a backend that cannot sign a transaction must carry no `SignTransaction` method at all. Fordefi is `fordefi.BlackBoxSigner` / `fordefi.NativeAutoSigner`, picked by `Config.Chain`.
- **Crossmint is sending-only** and Utila is transaction-only, and in TS each must expose *no* method for what it does not support rather than a throwing one: Kit classifies signers by duck-typed method presence, so a stub would misclassify them. This is why Crossmint is excluded from `@solana/keychain-kit-plugin` at the type level.
- **CDP** accepts UTF-8 message payloads only.
- **Turnkey** response `r,s` must be left-padded to 32 bytes each before concatenation.
- **GCP KMS** uses PureEdDSA with `EC_SIGN_ED25519`.
- **Serialization** goes through the language's transaction helper, never `bincode`/`MarshalBinary` directly (`sdk-v4` needs `wincode` for v1; Python has `signed_message_bytes()` for the bytes a signature covers, never hand-roll the version prefix).
- **v1 transactions** require Rust `sdk-v4` and solana-go v2; they are unrepresentable under `sdk-v2`/`sdk-v3`.
- **Remote calls** go through the core HTTP helper (`fetchSignerJson`, `fetch_signer_json`, `core.NewHTTPClient`), which owns the error pipeline, sanitization, redirect rejection and timeouts. Batch signing uses the core staggered helper.
- **Unit tests mock HTTP** (`wiremock`, `respx`, `httptest`); no live API calls. Integration suites are marker/tag-gated and skip themselves when unconfigured.
- **Python extras:** the root `__init__.py` must never eagerly import a backend whose deps sit behind an optional extra, and such a backend must raise "install `solana-keychain[<extra>]`". New backends go in `keychain.py`'s `_BACKENDS` table.
- **Adding a backend to TS** touches the umbrella in 7 places (including the treeshake script) plus `typescript-ci.yml` and `typescript-publish.yml`.
- **No Go umbrella on purpose:** Go does not dead-code-eliminate across a runtime dispatch switch, so an umbrella would force every backend SDK into all consumers' builds.
