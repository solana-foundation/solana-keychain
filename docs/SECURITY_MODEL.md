# Security Model

`solana-keychain` validates the signing hop, never what a transaction does. Backends come in two shapes, and the difference matters before you put one on a path that moves value. Which shape a given backend has is in the signer-capabilities table of your language's README: [Rust](../rust/README.md#signer-capabilities), [TypeScript](../typescript/README.md#signer-capabilities), [Python](../python/README.md#signer-capabilities), [Go](../go/README.md#signer-capabilities).

**Signing backends sign the bytes you built.** The signature the provider returns is verified against your locally computed message before it is used, so you end up with a transaction you can still inspect and broadcast yourself. See the memory or Vault example in the quick-start.

**Sending backends sign bytes you never see.** The provider builds, rewrites (to sponsor gas) and broadcasts server-side, so the returned signature identifies the transaction that landed rather than covering the bytes you submitted, and there is nothing to verify it against. A failure may still have landed on chain, so reconcile before retrying. See Crossmint in the capabilities table and the sign-and-send section.
