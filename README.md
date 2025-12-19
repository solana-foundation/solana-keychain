# solana-keychain

**Flexible, framework-agnostic Solana transaction signing**

> ⚠️ **SECURITY NOTICE**: This library has not been audited. Use at your own risk. Not recommended for production use with real funds without a thorough security review. The authors and contributors are not responsible for any loss of funds or damages resulting from the use of this library.

`solana-keychain` provides a unified interface for signing Solana transactions with multiple backend implementations. Whether you need local keypairs for development, enterprise vault integration, or managed wallet services, this library offers a consistent API across all signing methods.

## Implementations

This repository contains two implementations:

### [Rust](rust/)

Framework-agnostic Rust library with async support and multiple signing backends.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS
- **Features**: Async/await, feature flags for zero-cost abstractions, SDK v2 & v3 support
- [View Rust Documentation →](rust/README.md)

### [TypeScript](typescript/)

Solana Kit compatible signer implementation for Node.js and browser environments.

- **Backends**: Memory, Vault, Privy, Turnkey, AWS KMS
- **Features**: Solana Kit compatible, tree-shakeable modules, full type safety
- [View TypeScript Documentation →](typescript/README.md)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT
