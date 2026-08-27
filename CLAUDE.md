# CLAUDE.md

One `SolanaSigner` contract over 14 backends in Rust, TypeScript, Python and Go, kept at cross-language parity: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Crossmint, CDP, Para, Openfort, Utila, Fordefi.

Layout: `rust/` (feature-gated crate), `typescript/` (pnpm monorepo, one package per backend plus `core` and the `keychain` umbrella), `python/` (single `solana-keychain` package, src layout), `go/` (one module per backend plus `core`, no umbrella). Adding a backend: [docs/ADDING_SIGNERS.md](docs/ADDING_SIGNERS.md).

## Commands

Always use `just`, never raw `cargo`/`pnpm`/`pytest`/`go test`: the recipes encode flags those get wrong. `just` with no args lists every recipe.

- `just build` / `test` / `fmt` / `test-integration` cover all four languages. `just <rust|ts|py|go>-*` scopes to one.
- `just rust-test` runs the `sdk-v2`, `sdk-v3` and `sdk-v4` matrices. `cargo test --all-features` fails: the SDK features are mutually exclusive.
- `just ts-treeshake` after touching TS exports; every package and the umbrella must stay tree-shakable.
- Integration recipes spawn their own local `vault server -dev` and load `.env`. Never start Vault or pass secrets yourself.
- Releases go through the [`release`](.claude/skills/release/SKILL.md) and [`complete-release`](.claude/skills/complete-release/SKILL.md) skills; CI wiring for a forked backend PR through [`add-signer-ci`](.claude/skills/add-signer-ci/SKILL.md). Check version consistency across **all** crates and packages.

## Security standing

Consumer-facing summary in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md); keep it in sync when a change alters the signing or sending shapes. Keychain is a signing adapter. It validates the signing hop, not the caller's intent: no simulation, no transaction-content checks, no policy engine, no key custody.

- **Signature binding.** A provider-returned signature is verified with ed25519 against locally computed message bytes at the signer's required position. Mismatch fails; it is never attached.
- **Trusted-provider model.** Where a provider rewrites the transaction (Crossmint gas sponsorship, Fordefi native mode), the returned signature covers *its* bytes, not the caller's, and is not diffable. Crossmint's `SignerSecret` auto-approval delegates the choice of what gets approved to Crossmint.
- **Broadcast-managed signers** (Crossmint, Fordefi native mode) never mutate the caller's transaction, and a failure does not mean nothing landed. `BROADCAST_UNCONFIRMED` carries a provider transaction id only when the create was accepted; without one, recovery rests on the message-derived idempotency key, which makes a byte-identical resend safe and a rebuilt transaction a new transfer.
- **Redacted errors.** `SignerError` messages, `Debug`/`repr`, and sanitized remote bodies must never carry key material or raw provider responses. Callers match stable codes.
- **Redirects always rejected**, timeouts always set, HTTPS enforced on configured base URLs. Two carve-outs: Vault allows plain-HTTP loopback for `vault server -dev`, and the KMS backends use their vendor SDK's transport. Signing before `init()` fails rather than using the zero address.
- **Pinned wire format.** Golden vectors freeze the serialized bytes; never regenerate them to make a suite pass.
- Rust zeroizes intermediate key buffers. Go and Python cannot: treat the whole process memory as sensitive with local-key backends.
- Audit covers Rust and TypeScript through one commit; Python and Go are entirely unaudited. See [audits/AUDIT_STATUS.md](audits/AUDIT_STATUS.md).

## Cross-language gotchas

- **`init()` before use** for Privy, Fireblocks, Dfns, Crossmint, Para, Openfort. The `Signer::from_*` (Rust) and `await createXSigner(...)` / `create_keychain_signer(...)` factories do it for you; direct construction skips it.
- **Rust capability is in the type.** `SolanaSigner` is the base (pubkey, sign_message, is_available); a backend implements exactly one of `TransactionSigner`, `ModifyingSigner` or `SendingSigner`. The umbrella `Signer` enum implements only the base trait; capabilities are reached through `as_transaction_signer()` / `as_sending_signer()` (`None` when absent) or its own variant-routing `sign_and_send`. Fordefi is two types (`FordefiBlackBoxSigner`, `FordefiNativeAutoSigner`), picked by `config.chain`. TS mirrors this: `SolanaSigner` is the union `SolanaTransactionSigner | SolanaModifyingSigner | SolanaSendingSigner` (narrow with the `isSolana*Signer` guards), `SolanaMessageSigner` is orthogonal, and Utila is transaction-only with no `signMessages` method.
- **Crossmint is sending-only.** `sign_and_send_transaction` / `signAndSendTransactions` only; the sign-only entry point fails, and `signMessages` is unsupported. In Rust it implements `SendingSigner` and no `TransactionSigner`. In TS it is `CrossmintSendingSigner` (a `SolanaSendingSigner`) and deliberately exposes no `signTransactions` or `signMessages`, because Kit classifies signers by duck-typed method presence, so it is excluded from `@solana/keychain-kit-plugin` at the type level.
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

## Branches

`main` is the integration branch (audited plus unaudited). Topic branches are `feat/*`, `fix/*`, `chore/*` off `main`; urgent fixes are `hotfix/*` off a deployed stable tag via `just hotfix`. `just branch-info` prints the full guidance.
