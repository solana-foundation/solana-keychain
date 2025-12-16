/**
 * Configuration for creating an AwsKmsSigner
 */
export interface AwsKmsSignerConfig {
    /** AWS KMS key ID or ARN (must be an ECC_NIST_EDWARDS25519 key) */
    keyId: string;
    /** Solana public key (base58) corresponding to the AWS KMS key */
    publicKey: string;
    /** Optional AWS region (defaults to default region from AWS config) */
    region?: string;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
    /** Optional AWS credentials (defaults to default credential provider chain) */
    credentials?: AwsCredentials;
}

/**
 * AWS credentials configuration
 */
export interface AwsCredentials {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
}

/**
 * AWS KMS key metadata for validation
 */
export interface KmsKeyMetadata {
    /** The key ID */
    KeyId: string;
    /** The AWS account ID that owns the key */
    AWSAccountId?: string;
    /** The key spec (must be ECC_NIST_EDWARDS25519 for EdDSA) */
    KeySpec?: 'ECC_NIST_EDWARDS25519' | string;
    /** The key usage (must be SIGN_VERIFY for signing) */
    KeyUsage?: 'SIGN_VERIFY' | 'ENCRYPT_DECRYPT' | string;
    /** The key state */
    KeyState?: 'Enabled' | 'Disabled' | 'PendingDeletion' | 'PendingImport' | string;
}
