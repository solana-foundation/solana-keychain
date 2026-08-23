# solana-keychain (Go)

**Flexible, framework-agnostic Solana transaction signing for Go applications**

`solana-keychain` provides a unified interface for signing Solana transactions
with multiple backend implementations. Whether you need local keypairs for
development, enterprise vault integration, or managed wallet services, this
library offers a consistent API across all signing methods.

## Features

- **Unified interface**: a single `Signer` interface for every backend
- **Context-aware**: methods take `context.Context` and block — idiomatic Go, no callbacks
- **Per-backend modules**: each backend is its own Go module, so both your build and your module graph contain only the backends you import
- **Verified wire format**: golden-vector tests pin the exact serialized transaction bytes, so serialization can never silently drift
- **Safe errors**: `SignerError` redacts sensitive detail from its message; match on stable codes with `errors.Is`
- **Minimal core**: built on [`gagliardetto/solana-go`](https://github.com/gagliardetto/solana-go); heavy vendor SDKs land only in the backends that need them

## Supported Backends

| Backend | Use Case | Package | Status |
| --- | --- | --- | --- |
| **Memory** | Local keypairs, development, testing | `signers/memory` | ✅ Available |
| **Vault** | Enterprise key management with HashiCorp Vault | `signers/vault` | ✅ Available |
| **Turnkey** | Non-custodial key management via Turnkey | `signers/turnkey` | ✅ Available |
| **AWS KMS** | AWS Key Management Service with Ed25519 signing | `signers/awskms` | ✅ Available |
| **GCP KMS** | Google Cloud Key Management Service with Ed25519 signing | `signers/gcpkms` | ✅ Available |
| **Fireblocks** | Fireblocks institutional custody platform | `signers/fireblocks` | ✅ Available |
| **Privy** | Embedded wallets with Privy infrastructure | `signers/privy` | ✅ Available |
| **Dfns** | Dfns wallet infrastructure with Ed25519 signing | `signers/dfns` | ✅ Available |
| **CDP** | Coinbase Developer Platform managed wallets | `signers/cdp` | ✅ Available |
| **Para** | MPC wallets with Para infrastructure | `signers/para` | ✅ Available |
| **Crossmint** | Crossmint managed wallets | `signers/crossmint` | ✅ Available |
| **Openfort** | Openfort backend wallets with TEE-stored keys | `signers/openfort` | ✅ Available |
| **Utila** | Utila MPC wallet integration | `signers/utila` | ✅ Available |
| **Fordefi** | Fordefi institutional MPC custody | `signers/fordefi` | ✅ Available |

## Installation

Every backend is its own Go module, so your dependency graph contains only the
backend you import (a memory-only consumer pulls no AWS/GCP SDKs and no
`google.golang.org/api` toolchain floor):

```bash
go get github.com/solana-foundation/solana-keychain/go/signers/memory@latest
go get github.com/solana-foundation/solana-keychain/go/signers/vault@latest
```

Requires **Go 1.25+** (the `gcpkms` module requires the toolchain floor set by
`google.golang.org/api`). Built on
[`github.com/gagliardetto/solana-go`](https://github.com/gagliardetto/solana-go)
for the on-chain types and canonical transaction serialization.

### v1 transactions pin an unreleased solana-go

No released solana-go decodes v1
([PR #481](https://github.com/solana-foundation/solana-go/pull/481) is unmerged),
so every module carries a `replace` onto that pull request's branch:

```
replace github.com/gagliardetto/solana-go => github.com/sonicfromnewyoke/solana-go v0.0.0-20260817125726-409ee9873f6d
```

This is a development pin, not a release configuration: the fork branch can be
rebased or deleted, and `replace` does not reach consumers of a published module.
Drop the directives and require a released version once PR #481 lands.

Until the first `go/...` version tags are published, `@latest` cannot resolve
the in-repo `go/core` dependency. The signer modules use `replace` directives
during development, and `replace` only applies to the main module — a signer is
publishable only once its `require`s point at real released versions. The
release sequence is therefore:

1. Tag and push `go/core/vX.Y.Z` and `go/testutils/vX.Y.Z` (`core` has no
   in-repo dependencies — not even in its tests — so it is always taggable
   first).
2. Run `just go-release-prep vX.Y.Z` to drop the `replace` directives and pin
   the released versions in every signer module; commit.
3. Tag and push `go/signers/<name>/vX.Y.Z` for each signer.

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

### Remote Backends

Every remote backend follows the same pattern: a `Config` struct and a `New`
constructor that returns a ready-to-use signer (backends that need a remote
lookup take a `context.Context` and perform it inline):

```go
import "github.com/solana-foundation/solana-keychain/go/signers/vault"

signer, err := vault.New(vault.Config{
	VaultAddr: "https://vault.example.com",
	Token:     os.Getenv("VAULT_TOKEN"),
	KeyName:   "my-solana-key",
	Pubkey:    "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR",
})
```

```go
import "github.com/solana-foundation/solana-keychain/go/signers/privy"

signer, err := privy.New(ctx, privy.Config{
	AppID:     os.Getenv("PRIVY_APP_ID"),
	AppSecret: os.Getenv("PRIVY_APP_SECRET"),
	WalletID:  os.Getenv("PRIVY_WALLET_ID"),
})
```

Remote HTTP backends accept an optional `HTTPClient` override in their config;
when unset, requests go through an HTTPS-enforcing client built from
`core.HTTPClientConfig` timeouts.
The KMS backends (`awskms`, `gcpkms`) expose the equivalent SDK-level client
override instead.

### Fordefi Signing Modes

Fordefi supports three transaction modes:

- **Black box** (`Chain` empty): signs the caller's exact message bytes, updates
  the transaction locally, and returns its base64 wire encoding for the caller
  to broadcast.
- **Native auto** (`Chain` set and `PushMode` empty or `PushModeAuto`): Fordefi
  may modify the transaction, signs it, and broadcasts it. The caller's
  transaction is intentionally left untouched and `EncodedTransaction` is
  empty because it must not be sent again.
- **Native manual** (`Chain` set and `PushModeManual`): Fordefi may replace the
  recent blockhash and manage `SetComputeUnitPrice`/`SetComputeUnitLimit`, then
  signs the transaction without broadcasting it. Every other message field is
  validated exactly. `SignTransaction` replaces the caller's
  `*solana.Transaction` with Fordefi's validated result and returns a non-empty
  base64 wire transaction. Custom unit prices must match and custom priority
  fees cap the effective returned fee.

Manual mode must run first with the Fordefi vault as fee payer. Single-signer
results are complete and ready for caller-managed broadcasting. Multisigner
results are partial: add every downstream signature to the replaced `tx`, then
serialize that completed transaction rather than broadcasting the earlier
partial encoding.

```go
import "github.com/solana-foundation/solana-keychain/go/signers/fordefi"

signer, err := fordefi.New(ctx, fordefi.Config{
	AccessToken:   os.Getenv("FORDEFI_ACCESS_TOKEN"),
	VaultID:       os.Getenv("FORDEFI_VAULT_ID"),
	PublicKey:     os.Getenv("FORDEFI_PUBLIC_KEY"),
	PrivateKeyPEM: os.Getenv("FORDEFI_PRIVATE_KEY_PEM"),
	Chain:         fordefi.ChainSolanaDevnet,
	PushMode:      fordefi.PushModeManual,
})
if err != nil {
	return err
}

result, err := signer.SignTransaction(ctx, tx)
if err != nil {
	return err
}
// tx now contains Fordefi's authoritative message and signature. If
// result.IsComplete(), result.EncodedTransaction can be sent to Solana RPC.
```

Fordefi can replace the recent blockhash but does not return its
`lastValidBlockHeight`. Go retains the replacement blockhash in `tx`; broadcast
manual results promptly rather than relying on local block-height expiry
detection.

Mutation eligibility depends on whether signatures are supplied, not on
`push_mode`. This SDK's native manual request is unsigned, omits
`details.signatures`, and rejects pre-signed inputs, so Fordefi may refresh the
blockhash and manage fees. A future provided-signatures flow must preserve the
complete message byte-for-byte. `push_mode` controls submission only.
Durable-nonce transactions keep both their lifetime and fee layout exact; v1
transactions may replace only the blockhash and keep their inline configuration exact.

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
[`core`](core/) package:

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
present.

## Packages

| Package | Description |
| --- | --- |
| [`core`](core/) | `Signer` interface, `SignedTransaction`, error types, transaction & HTTP utilities, batch helpers |
| [`signers/memory`](signers/memory/) | In-memory Ed25519 signer — local keypairs for development and testing |
| [`signers/vault`](signers/vault/) | HashiCorp Vault transit engine |
| [`signers/turnkey`](signers/turnkey/) | Turnkey (P-256 API-key request stamping) |
| [`signers/awskms`](signers/awskms/) | AWS KMS (`ECC_NIST_EDWARDS25519` keys) |
| [`signers/gcpkms`](signers/gcpkms/) | Google Cloud KMS (`EC_SIGN_ED25519`, PureEdDSA) |
| [`signers/fireblocks`](signers/fireblocks/) | Fireblocks (RAW / PROGRAM_CALL flows with status polling) |
| [`signers/privy`](signers/privy/) | Privy wallet API |
| [`signers/dfns`](signers/dfns/) | Dfns (User Action Signing challenge flow) |
| [`signers/cdp`](signers/cdp/) | Coinbase Developer Platform (EdDSA bearer + ES256 wallet-auth JWTs) |
| [`signers/para`](signers/para/) | Para wallet API |
| [`signers/crossmint`](signers/crossmint/) | Crossmint (create/poll/approve flow, HKDF delegated-signer key) |
| [`signers/openfort`](signers/openfort/) | Openfort (ES256 x-wallet-auth JWTs) |
| [`signers/fordefi`](signers/fordefi/) | Fordefi (black-box, native auto, or native manual Solana MPC signing with status polling and P-256 request signing) |
| [`testutils`](testutils/) | Deterministic keypair + test-transaction helpers for testing your own signers |

Backend-behavior quirks: `crossmint` intentionally does not support
`SignMessage` (returns `SIGNER_SIGNING_FAILED`), and `cdp` only accepts UTF-8
message payloads.

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

Go offers no reliable way to zero memory: the garbage collector may copy and
retain key bytes (`memory` keypairs, derived Crossmint/Openfort keys) until
collection, and finalizer-based scrubbing gives no guarantee. Treat the whole
process memory as sensitive when using local-key backends.

## Contributing

Local development uses [Just](https://github.com/casey/just) as the task runner:

```bash
just go-build              # compile
just go-test               # unit tests
just go-fmt                # gofmt + go vet + golangci-lint
just go-test-integration   # integration tests (spins up local Vault, loads .env)
```

Serialization is guarded by golden wire-format vectors pinned in
[`core/parity_test.go`](core/parity_test.go): the base64 of a deterministic
signed transaction is frozen and must never be regenerated to make the suite
pass.

## Roadmap

- Publish workflow (tag `go/vX.Y.Z`) and Go presentation in the root
  README / docs.
- Fork-contributed live-test support for Go backends.

### Why there is no umbrella package

Go performs no dead-code elimination across a runtime dispatch switch: an
umbrella package would force the AWS and GCP SDKs (and every other backend
dependency) into all consumers' builds. Importing the backend package you need
is the Go-native selector and keeps dependency isolation exact, so an umbrella
is intentionally omitted.
