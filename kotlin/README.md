# solana-keychain (Kotlin)

**Solana transaction signing for Kotlin on JVM and Android**

The Kotlin implementation of the `solana-keychain` signer contract. Calls block,
as in Go. Ed25519 comes from [BouncyCastle](https://www.bouncycastle.org/),
because the JDK cannot derive a public key from a seed.

## Supported Backends

| Backend | Use Case | Package | Status |
| --- | --- | --- | --- |
| **Memory** | Local keypairs, development, testing | `com.solana.keychain.memory` | ✅ Available |

## Installation

No artifact is published yet. Build from this directory with JDK 17 and
Gradle 9.7.1 (the version `kotlin-ci.yml` pins):

```bash
gradle installDist   # jar and BouncyCastle under build/install/solana-keychain/lib
```

## Quick Start

### Memory Signer

```kotlin
import com.solana.keychain.memory.MemorySigner

// A base58 64-byte key or a "[1,2,...]" byte array.
val signer = MemorySigner.fromPrivateKeyString("[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,...]")
// Also: MemorySigner.fromBytes(seedOrKeypair), MemorySigner.fromKeypairFile("id.json")

println(signer.address)
```

### Sign a message

```kotlin
val signature: ByteArray = signer.signMessage("Hello Solana!".toByteArray())
```

### Sign a transaction

`signTransaction` takes wire bytes of a legacy or v0 transaction:

```kotlin
val signed = signer.signTransaction(wireBytes)
signed.encodedTransaction // base64 wire transaction
signed.signature          // this signer's signature
signed.isComplete         // are all required signatures present?
```

## Errors

Every failure is a `SignerError`. Its `message` and `toString()` carry only the
code's fixed generic message; the detail stays in `detail`. Match on `code`:

| Code | Raised when |
| --- | --- |
| `SIGNER_INVALID_PRIVATE_KEY` | A key is not 32 or 64 bytes, a 64-byte key's public half does not match its seed, or a string or file does not decode to 64 bytes |
| `SIGNER_IO_ERROR` | A keypair file cannot be read |
| `SIGNER_SERIALIZATION_ERROR` | A transaction is truncated, has trailing bytes, a non-canonical length, an unsupported version, fewer account keys or more signatures than its header requires |
| `SIGNER_SIGNING_FAILED` | The signer is not a required signer of the transaction |

## Security

The Kotlin implementation is **not audited**. Audit status is tracked in
[audits/AUDIT_STATUS.md](../audits/AUDIT_STATUS.md).

Decoded key bytes are zeroed after parsing, but the JVM may copy them, and the
signer holds its seed for its lifetime. Treat process memory as sensitive.

## Contributing

```bash
just kotlin-build   # gradle installDist
just kotlin-test    # unit tests
just kotlin-fmt     # spotlessApply (ktlint)
just kotlin-check   # spotlessCheck + unit tests
```

The golden wire-format vectors in `MemorySignerTest.kt` are frozen and must
never be regenerated to make the suite pass.
