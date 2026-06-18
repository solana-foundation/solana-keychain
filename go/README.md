# solana-keychain (Go)

**Flexible, framework-agnostic Solana transaction signing for Go applications**

`solana-keychain` provides a unified interface for signing Solana transactions
with multiple backend implementations. Whether you need local keypairs for
development, enterprise vault integration, or managed wallet services, this
library offers a consistent API across all signing methods — with full parity to
the [Rust](../rust/README.md) and [TypeScript](../typescript/README.md) libraries.

> **Status: foundation phase.** The shared `core` contract and the `memory`
> backend are implemented, tested, and ready to use. The remaining backends
> (Vault, Turnkey, AWS KMS, …) are being added incrementally — see [Roadmap](#roadmap).

## Features

- **Unified interface**: a single `Signer` interface for every backend
- **Context-aware**: methods take `context.Context` and block — idiomatic Go, no callbacks
- **Automatic backend selection**: importing a backend links only what it needs; the compiler excludes backends you don't import (the Go-native equivalent of Rust feature flags and the TS per-package split)
- **Cross-language parity**: the same signing contract and behavior as the Rust and TypeScript implementations, verified down to byte-identical transaction serialization
- **Safe errors**: `SignerError` redacts sensitive detail from its message; match on stable codes with `errors.Is`
- **Minimal core**: built on [`gagliardetto/solana-go`](https://github.com/gagliardetto/solana-go); heavy vendor SDKs land only in the backends that need them

## Supported Backends

| Backend | Use Case | Package | Status |
| --- | --- | --- | --- |
| **Memory** | Local keypairs, development, testing | `signers/memory` | ✅ Available |
| **Vault** | Enterprise key management with HashiCorp Vault | `signers/vault` | 🚧 Planned |
| **Turnkey** | Non-custodial key management via Turnkey | `signers/turnkey` | 🚧 Planned |
| **AWS KMS** | AWS Key Management Service with Ed25519 signing | `signers/awskms` | 🚧 Planned |
| **GCP KMS** | Google Cloud Key Management Service with Ed25519 signing | `signers/gcpkms` | 🚧 Planned |
| **Fireblocks** | Fireblocks institutional custody platform | `signers/fireblocks` | 🚧 Planned |
| **Privy** | Embedded wallets with Privy infrastructure | `signers/privy` | 🚧 Planned |
| **Dfns** | Dfns wallet infrastructure with Ed25519 signing | `signers/dfns` | 🚧 Planned |
| **CDP** | Coinbase Developer Platform managed wallets | `signers/cdp` | 🚧 Planned |
| **Para** | MPC wallets with Para infrastructure | `signers/para` | 🚧 Planned |
| **Crossmint** | Crossmint managed wallets | `signers/crossmint` | 🚧 Planned |
| **Openfort** | Openfort backend wallets with TEE-stored keys | `signers/openfort` | 🚧 Planned |

Planned backends will reach full 12-backend parity with the Rust and TypeScript
libraries — see [Roadmap](#roadmap).

## Installation

```bash
go get github.com/solana-foundation/solana-keychain/go@latest
```

Requires **Go 1.25+**. Built on [`github.com/gagliardetto/solana-go`](https://github.com/gagliardetto/solana-go)
for the on-chain types and canonical transaction serialization.

## Quick Start

### Memory Signer (Local Development)

```go
package main

import (
	"context"
	"fmt"

	"github.com/solana-foundation/solana-keychain/go/signers/memory"
)

func main() {
	ctx := context.Background()

	// Build a signer from a base58 key, a "[1,2,...]" byte array, raw bytes,
	// or a Solana CLI keypair file.
	signer, err := memory.New(memory.Config{
		PrivateKeyString: "[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,...]",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("address:", signer.Pubkey())

	// Sign an arbitrary message.
	sig, err := signer.SignMessage(ctx, []byte("Hello Solana!"))
	if err != nil {
		panic(err)
	}
	fmt.Println("signature:", sig)

	// Sign a transaction (tx is a *solana.Transaction):
	//   res, err := signer.SignTransaction(ctx, tx)
	//   res.EncodedTransaction  // base64 wire transaction
	//   res.Signature           // this signer's signature
	//   res.IsComplete()        // are all required signatures present?
}
```

### Batch Signing

Single-item methods match the contract 1:1; batch signing is provided as free
helpers (concurrent, with an optional per-request stagger for rate-limited APIs):

```go
sigs, err := core.SignMessages(ctx, signer, [][]byte{msg1, msg2}, core.BatchOptions{
	MaxConcurrency: 4,             // 0 = unbounded
	RequestDelay:   50 * time.Millisecond,
})
```

## Core API

Every signer implements the `Signer` interface from the
[`core`](core/) package — the Go analog of the Rust `SolanaSigner` trait and the
TypeScript `SolanaSigner` interface:

```go
type Signer interface {
	// Pubkey returns this signer's Solana public key.
	Pubkey() solana.PublicKey

	// SignTransaction signs tx in place and returns the encoded transaction,
	// the signature, and whether all required signatures are now present.
	SignTransaction(ctx context.Context, tx *solana.Transaction) (SignedTransaction, error)

	// SignMessage signs arbitrary bytes and returns the 64-byte signature.
	SignMessage(ctx context.Context, message []byte) (solana.Signature, error)

	// IsAvailable reports whether the signer is reachable and healthy.
	IsAvailable(ctx context.Context) bool
}
```

`SignTransaction` returns a `SignedTransaction { EncodedTransaction, Signature,
Completeness }`; use `IsComplete()` to check whether every required signature is
present (the Go analog of the Rust `Complete`/`Partial` result).

## Packages

| Package | Description |
| --- | --- |
| [`core`](core/) | `Signer` interface, `SignedTransaction`, error types, transaction & HTTP utilities, batch helpers |
| [`signers/memory`](signers/memory/) | In-memory Ed25519 signer — local keypairs for development and testing |
| [`testutils`](testutils/) | Deterministic keypair + test-transaction helpers for testing your own signers |

### Notes for Go consumers

- **Selective backends are automatic.** Importing `signers/memory` links only
  `solana-go` + the standard library; the Go compiler excludes backends you don't
  import. There is no "feature flag" to set — the import graph is the selector.
- **Errors are redacting.** `core.SignerError` never prints its detail or wrapped
  cause via `Error()`; only a fixed, generic message per `core.Code` is surfaced.
  Match codes with `errors.Is(err, ...)` or `core.CodeOf(err)`.
- **HTTPS is enforced** for remote backends via `core.NewHTTPClient`, which rejects
  any non-`https` request.

## Security

The published [Accretion audit](../audits/2026-accretion-solana-foundation-solana-keychain-audit-A26SFR2.pdf)
covers the Rust and TypeScript implementations. The Go implementation is new and
has **not** yet been independently audited. Audit status is tracked in
[audits/AUDIT_STATUS.md](../audits/AUDIT_STATUS.md).

## Contributing

Local development uses [Just](https://github.com/casey/just) as the task runner:

```bash
just go-build              # compile
just go-test               # unit tests
just go-fmt                # gofmt + go vet + golangci-lint
just go-test-integration   # integration tests (spins up local Vault, loads .env)
```

Cross-language serialization parity is guarded by a pinned golden vector in
[`core/parity_test.go`](core/parity_test.go): the base64 of a deterministic signed
transaction must stay byte-identical to the Rust and TypeScript output.

## Roadmap

- Remote backends to reach 12-backend parity: `vault`, `turnkey`, `awskms`,
  `gcpkms`, `fireblocks`, `privy`, `dfns`, `cdp`, `para`, `crossmint`, `openfort`.
- `keychain` umbrella package: a `NewSigner(ctx, Config)` dispatcher mirroring the
  TS `createKeychainSigner`.
- CI workflow (`go-ci.yml`), publish workflow (tag `go/vX.Y.Z`), and three-language
  presentation in the root README / docs.
