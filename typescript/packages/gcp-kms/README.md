# @solana/keychain-gcp-kms

Google Cloud KMS-based signer for Solana transactions using EdDSA (Ed25519) signing.

## Installation

```bash
pnpm add @solana/keychain-gcp-kms
```

## Prerequisites

1. A Google Cloud KMS key with:
   - **Algorithm**: `EC_SIGN_ED25519`
   - **Purpose**: `ASYMMETRIC_SIGN`

2. Google Cloud credentials configured (see [Google Cloud Credentials](#google-cloud-credentials) below)

## Google Cloud Credentials

The signer uses the **Application Default Credentials (ADC)** to authenticate. You don't need to pass credentials explicitly when running in a Google Cloud environment (Compute Engine, GKE, Cloud Run, etc.).

### IAM Permissions

For this signer:

- Signing operations require `cloudkms.cryptoKeyVersions.useToSign`
- Availability checks (`isAvailable()`) require `cloudkms.cryptoKeyVersions.viewPublicKey`

### Local Development

For local development, you can:

1. **Use the gcloud CLI**:
   ```bash
   gcloud auth application-default login
   ```

2. **Use a Service Account Key**:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service-account-file.json"
   ```

## Creating a Google Cloud KMS Key

Use the `gcloud` CLI to create a key suitable for Solana signing:

```bash
# Create a KeyRing
gcloud kms keyrings create "my-keyring" --location "us-east1"

# Create a CryptoKey
gcloud kms keys create "my-key" \
  --location "us-east1" \
  --keyring "my-keyring" \
  --purpose "asymmetric-signing" \
  --default-algorithm "ec-sign-ed25519"
```

## Usage

### Basic Example

```typescript
import { createGcpKmsSigner } from '@solana/keychain-gcp-kms';

const signer = createGcpKmsSigner({
    keyName: 'projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1',
    publicKey: 'YourSolanaPublicKeyBase58',
});

// Sign a message
const message = { content: new Uint8Array([1, 2, 3, 4]) };
const signatures = await signer.signMessages([message]);

// Sign a transaction
const signatures = await signer.signTransactions([transaction]);
```

## API Reference

### `GcpKmsSigner`

#### Constructor

```typescript
createGcpKmsSigner(config: GcpKmsSignerConfig)
```

**Config Options:**
- `keyName` (required): Full resource name of the GCP KMS crypto key version
- `publicKey` (required): Solana public key (base58-encoded)
- `requestDelayMs` (optional): Delay in ms between concurrent signing requests to avoid rate limits (default: 0)

#### Properties

- `address`: The Solana address (public key) for this signer

#### Methods

- `signMessages(messages)`: Sign multiple messages
- `signTransactions(transactions)`: Sign multiple transactions
- `isAvailable()`: Check if the signer is available by retrieving the public key and verifying `EC_SIGN_ED25519`
