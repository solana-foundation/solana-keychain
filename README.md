# solana-keychain

**Flexible, framework-agnostic Solana transaction signing**

`solana-keychain` provides a unified interface for signing Solana transactions with multiple backend implementations. Whether you need local keypairs for development, enterprise vault integration, or managed wallet services, this library offers a consistent API across all signing methods.

## Implementations

This repository contains two implementations:

### [Rust](rust/)

Framework-agnostic Rust library with async support and multiple signing backends.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint
- **Features**: Async/await, feature flags for zero-cost abstractions, SDK v2 & v3 support
- [View Rust Documentation →](rust/README.md)

### [TypeScript](typescript/)

Solana Kit compatible signer implementation for Node.js and browser environments.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS, Fireblocks, GCP KMS, Dfns, Para, CDP, Crossmint
- **Features**: Solana Kit compatible, tree-shakeable modules, full type safety
- [View TypeScript Documentation →](typescript/README.md)

## Security Audit

`solana-keychain` has been audited by [Accretion](https://accretion.xyz). View the [audit report](audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf).

Audit status, audited-through commit, and the current unaudited delta are tracked in [audits/AUDIT_STATUS.md](audits/AUDIT_STATUS.md).

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

[MIT](LICENSE)
