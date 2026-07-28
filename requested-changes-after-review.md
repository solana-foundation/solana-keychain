<h3>Greptile Summary</h3>

Adds Fordefi signing support across the Rust and TypeScript implementations.

- Implements native Solana and black-box transaction/message signing with request authentication and polling.
- Integrates Fordefi into the Rust signer enum and TypeScript umbrella factory.
- Adds package, CI, release, documentation, unit-test, integration-test, and tree-shaking wiring.

<h3>Confidence Score: 2/5</h3>

The PR is not safe to merge until native-mode signature handling and invalid polling configuration are corrected.

TypeScript native mode can return a signature for a different message than the caller supplied, Rust native mode rejects valid non-first Fordefi signatures, and both implementations can submit remote signing work before immediately timing out without polling.

**Files Needing Attention:** typescript/packages/fordefi/src/fordefi-signer.ts, rust/src/fordefi/mod.rs

<h3>Important Files Changed</h3>




| Filename | Overview |
|----------|----------|
| rust/src/fordefi/mod.rs | Implements Fordefi's Rust signing lifecycle, but native multi-signer signature selection and zero-attempt polling need correction. |
| typescript/packages/fordefi/src/fordefi-signer.ts | Implements the TypeScript Fordefi signer, but native mode returns a signature that may not apply to the caller's input transaction and accepts invalid polling attempts. |
| typescript/packages/keychain/src/create-keychain-signer.ts | Correctly adds dynamically imported Fordefi dispatch to the umbrella factory. |
| typescript/packages/keychain/src/resolve-address.ts | Routes Fordefi address resolution through signer initialization and remote vault verification. |
| rust/src/lib.rs | Adds feature-gated Fordefi construction and trait dispatch to the unified Rust signer. |
| .github/workflows/typescript-publish.yml | Adds the Fordefi package to manual publication and release metadata. |


## Breakdown


### In typescript/packages/fordefi/src/fordefi-signer.ts

When Fordefi changes the blockhash or fees in native mode, this returns a signature over Fordefi's modified wire transaction through `signTransactions`, whose caller applies it to the original input transaction, causing that assembled transaction to fail signature verification.

**Reply after change:** Resolved. Native mode now uses Kit's `TransactionSendingSigner` contract through `signAndSendTransactions`, returns the broadcast transaction signature from Fordefi's returned wire transaction, and verifies the vault signature against the returned message. Calling partial-signer `signTransactions` in native mode now fails locally before any remote signing request, and the devnet test no longer re-broadcasts the original transaction.

**Knowledge Base Used:** [Core Architecture: the SolanaSigner Abstraction](https://app.greptile.com/solana-foundation/-/custom-context/knowledge-base/solana-foundation/solana-keychain/-/docs/core-architecture.md)

### In rust/src/fordefi/mod.rs

When Fordefi is not signer index zero in a multi-signer native transaction, `signatures.first()` selects another signer's signature and verifies it against Fordefi's public key, causing a valid Fordefi signing result to return `SigningFailed`.

**Reply after change:** Resolved. Rust now finds Fordefi's required-signer account position with `TransactionUtil::get_signing_keypair_position` and reads the signature from that slot instead of assuming index zero. A regression test covers a valid Fordefi signature in the second slot. Native auto-broadcast also rejects unsupported multi-signer inputs before submission until their partial signatures can be forwarded to Fordefi.

**Knowledge Base Used:** [Core Architecture: the SolanaSigner Abstraction](https://app.greptile.com/solana-foundation/-/custom-context/knowledge-base/solana-foundation/solana-keychain/-/docs/core-architecture.md)


### In typescript/packages/fordefi/src/fordefi-signer.ts

When `maxPollAttempts` is zero, the signer submits the remote signing operation but executes no status request before reporting a polling timeout; Rust accepts the equivalent zero setting as well, leaving valid remote work running while the caller receives failure.

**Reply after change:** Resolved. TypeScript now requires `maxPollAttempts` to be a positive integer and validates it before the vault verification or transaction submission network calls. Rust now rejects `max_poll_attempts: Some(0)` during signer construction. Regression tests cover both configurations and confirm TypeScript performs no network request for invalid polling settings.

**Knowledge Base Used:** [Core Architecture: the SolanaSigner Abstraction](https://app.greptile.com/solana-foundation/-/custom-context/knowledge-base/solana-foundation/solana-keychain/-/docs/core-architecture.md)
