# solana-keychain

**Flexible, framework-agnostic Solana transaction signing**

`solana-keychain` provides a unified interface for signing Solana transactions with multiple backend implementations. Whether you need local keypairs for development, enterprise vault integration, or managed wallet services, this library offers a consistent API across all signing methods.

## Implementations

This repository contains five implementations:

### [Rust](rust/)

Framework-agnostic Rust library with async support and multiple signing backends.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila, Fordefi, Ledger (opt-in, unaudited)
- **Features**: Async/await, feature flags for zero-cost abstractions, SDK v2, v3 & v4 support
- [View Rust Documentation →](rust/README.md)

### [TypeScript](typescript/)

Solana Kit compatible signer implementation for Node.js and browser environments.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila, Fordefi
- **Features**: Solana Kit compatible, tree-shakeable modules, full type safety
- [View TypeScript Documentation →](typescript/README.md)

### [Python](python/)

Async signer library built on [`solders`](https://pypi.org/project/solders/) for canonical transaction serialization.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila, Fordefi
- **Features**: Async/await, optional extras so heavy provider SDKs stay out of the base install, strict typing
- [View Python Documentation →](python/README.md)

### [Go](go/)

Async-free signer library built on [`solana-go`](https://github.com/solana-foundation/solana-go), with one Go module per backend so your module graph contains only the backends you import.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint, Openfort, Utila, Fordefi
- **Features**: Per-backend modules, golden wire-format vectors, redacted errors matched by stable code
- [View Go Documentation →](go/README.md)

### [Kotlin](kotlin/)

Blocking JVM signer library with Ed25519 from [BouncyCastle](https://www.bouncycastle.org/), for Kotlin web3 libraries on JVM and Android.

- **Backends**: Memory
- **Features**: Wire-format v0 and legacy signing, golden wire-format vectors, redacted errors matched by stable code

## Security Model

`solana-keychain` is a signing adapter: it validates the signing hop, not what your transaction does. Backends come in two shapes, and only one of them signs the bytes you built. [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) is the short version, worth reading before putting a signer on a path that moves value.

To report a vulnerability, follow [SECURITY.md](SECURITY.md) rather than opening an issue.

## Security Audit

`solana-keychain` has been audited by [OtterSec](https://osec.io) (Rust, TypeScript, Python and Go; the Ledger backend was out of scope). View the [audit report](audits/2026-ottersec-solana-foundation-solana-keychain-audit.pdf). An earlier [Accretion](https://accretion.xyz) audit of the Rust and TypeScript implementations is also [available](audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf).

Audit status, audited-through commit, and the current unaudited delta are tracked in [audits/AUDIT_STATUS.md](audits/AUDIT_STATUS.md).

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

[MIT](LICENSE)
