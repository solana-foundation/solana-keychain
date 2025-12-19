# @solana-keychain/aws-kms

AWS KMS-based signer for Solana transactions using EdDSA (Ed25519) signing.

## Installation

```bash
pnpm add @solana-keychain/aws-kms @aws-sdk/client-kms
```

## Prerequisites

1. An AWS KMS key with:
   - **Key spec**: `ECC_NIST_EDWARDS25519`
   - **Key usage**: `SIGN_VERIFY`

2. AWS credentials configured (see [AWS Credentials](#aws-credentials) below)

## AWS Credentials

The signer uses the **AWS default credential provider chain** to authenticate. You don't need to pass credentials explicitly unless you want to override the defaults.

### Credential Resolution Order

The AWS SDK looks for credentials in this order:

1. **Environment variables**
   ```bash
   export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
   export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
   export AWS_SESSION_TOKEN="..." # Optional, for temporary credentials
   export AWS_REGION="us-east-1"  # Optional
   ```

2. **Shared credentials file** (`~/.aws/credentials`)
   ```ini
   [default]
   aws_access_key_id = AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   ```

3. **IAM role** (automatic when running on AWS EC2, ECS, or Lambda)

4. **Web identity token** (for EKS/Kubernetes with IRSA)

### Recommended Setup

| Environment | Recommended Method |
|-------------|-------------------|
| **Production on AWS** | IAM role attached to EC2/ECS/Lambda (no explicit creds needed) |
| **Local development** | Environment variables or `~/.aws/credentials` file |
| **CI/CD pipelines** | Environment variables or OIDC |
| **Explicit control** | Pass `credentials` in config (TypeScript only) |

### Security Best Practices

- **Never commit credentials** to source control
- **Use IAM roles** in production instead of long-lived access keys
- **Use least-privilege IAM policies** - only grant `kms:Sign` and `kms:DescribeKey`
- **Enable CloudTrail** to audit KMS key usage

## Creating an AWS KMS Key

Use the AWS CLI to create a key suitable for Solana signing:

```bash
aws kms create-key \
  --key-spec ECC_NIST_EDWARDS25519 \
  --key-usage SIGN_VERIFY \
  --description "Solana signing key"
```

Or use the AWS Console:
1. Go to AWS KMS → Customer managed keys
2. Click "Create key"
3. Select "Asymmetric" key type
4. Select "ECC_NIST_EDWARDS25519" key spec
5. Select "Sign and verify" key usage
6. Complete the key creation process

## Usage

### Basic Example

```typescript
import { AwsKmsSigner } from '@solana-keychain/aws-kms';

const signer = new AwsKmsSigner({
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    publicKey: 'YourSolanaPublicKeyBase58',
    region: 'us-east-1', // Optional, defaults to AWS config default
});

// Sign a message
const message = { content: new Uint8Array([1, 2, 3, 4]) };
const signatures = await signer.signMessages([message]);

// Sign a transaction
const signatures = await signer.signTransactions([transaction]);
```

### With Custom Credentials

```typescript
const signer = new AwsKmsSigner({
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    publicKey: 'YourSolanaPublicKeyBase58',
    region: 'us-east-1',
    credentials: {
        accessKeyId: 'your-access-key-id',
        secretAccessKey: 'your-secret-access-key',
        sessionToken: 'optional-session-token', // For temporary credentials
    },
});
```

### With Request Delay (Rate Limiting)

```typescript
const signer = new AwsKmsSigner({
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
    publicKey: 'YourSolanaPublicKeyBase58',
    requestDelayMs: 100, // 100ms delay between concurrent requests
});
```

## API Reference

### `AwsKmsSigner`

#### Constructor

```typescript
new AwsKmsSigner(config: AwsKmsSignerConfig)
```

**Config Options:**
- `keyId` (required): AWS KMS key ID or ARN
- `publicKey` (required): Solana public key (base58-encoded)
- `region` (optional): AWS region (defaults to AWS config default)
- `requestDelayMs` (optional): Delay in ms between concurrent requests (default: 0)
- `credentials` (optional): AWS credentials object

#### Methods

- `signMessages(messages)`: Sign multiple messages
- `signTransactions(transactions)`: Sign multiple transactions
- `isAvailable()`: Check if the signer is available and the key is valid

## AWS IAM Permissions

The AWS credentials used must have the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Sign",
                "kms:DescribeKey"
            ],
            "Resource": "arn:aws:kms:*:*:key/*"
        }
    ]
}
```

## Notes

- Ed25519 signatures are 64 bytes
- The signer uses `ED25519_SHA_512` algorithm with `RAW` message type
- The key must be in `Enabled` state to sign
- Rate limiting can be configured via `requestDelayMs` to avoid AWS KMS throttling

