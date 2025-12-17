import { DescribeKeyCommand, KMSClient, MessageType, SignCommand, SigningAlgorithmSpec } from '@aws-sdk/client-kms';
import { Address, assertIsAddress } from '@solana/addresses';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';
import { createSignatureDictionary, SignerErrorCode, SolanaSigner, throwSignerError } from '@solana-keychain/core';

import type { AwsCredentials, AwsKmsSignerConfig } from './types.js';

/**
 * AWS KMS-based signer using EdDSA (Ed25519) signing
 *
 * The AWS KMS key must be created with:
 * - Key spec: ECC_NIST_EDWARDS25519
 * - Key usage: SIGN_VERIFY
 *
 * Example AWS CLI command to create a key:
 * ```bash
 * aws kms create-key \
 *   --key-spec ECC_NIST_EDWARDS25519 \
 *   --key-usage SIGN_VERIFY \
 *   --description "Solana signing key"
 * ```
 */
export class AwsKmsSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly keyId: string;
    private readonly client: KMSClient;
    private readonly requestDelayMs: number;

    constructor(config: AwsKmsSignerConfig) {
        if (!config.keyId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required keyId field',
            });
        }

        if (!config.publicKey) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required publicKey field',
            });
        }

        try {
            assertIsAddress(config.publicKey);
            this.address = config.publicKey as Address<TAddress>;
        } catch (error) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana public key format',
            });
        }

        this.keyId = config.keyId;
        this.requestDelayMs = config.requestDelayMs || 0;
        this.validateRequestDelayMs(this.requestDelayMs);

        // Create AWS KMS client
        const clientConfig: {
            credentials?: AwsCredentials;
            region?: string;
        } = {};

        if (config.region) {
            clientConfig.region = config.region;
        }

        if (config.credentials) {
            clientConfig.credentials = config.credentials;
        }

        this.client = new KMSClient(clientConfig);
    }

    /**
     * Validate request delay ms
     */
    private validateRequestDelayMs(requestDelayMs: number): void {
        if (requestDelayMs < 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestDelayMs must not be negative',
            });
        }
        if (requestDelayMs > 3000) {
            console.warn(
                'requestDelayMs is greater than 3000ms, this may result in blockhash expiration errors for signing messages/transactions',
            );
        }
    }

    /**
     * Add delay between concurrent requests
     */
    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Sign message bytes using AWS KMS EdDSA signing
     */
    private async signBytes(messageBytes: Uint8Array): Promise<SignatureBytes> {
        try {
            const command = new SignCommand({
                KeyId: this.keyId,
                Message: messageBytes,
                MessageType: MessageType.RAW,
                SigningAlgorithm: SigningAlgorithmSpec.ED25519_SHA_512,
            });

            const response = await this.client.send(command);

            if (!response.Signature) {
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    message: 'No signature in AWS KMS response',
                });
            }

            // Ed25519 signatures are 64 bytes
            const signature = new Uint8Array(response.Signature);
            if (signature.length !== 64) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
                });
            }

            return signature as SignatureBytes;
        } catch (error: unknown) {
            // Re-throw SignerError as-is
            if (error instanceof Error && error.name === 'SignerError') {
                throw error;
            }
            if (error instanceof Error) {
                // AWS SDK errors
                const awsError = error as { $metadata?: { httpStatusCode?: number }; message?: string; name?: string };
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    cause: error,
                    message: `AWS KMS Sign operation failed: ${awsError.message || error.message}`,
                    status: awsError.$metadata?.httpStatusCode,
                });
            }
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                cause: error,
                message: 'AWS KMS Sign operation failed',
            });
        }
    }

    /**
     * Sign multiple messages using AWS KMS
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signBytes(messageBytes);
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Sign multiple transactions using AWS KMS
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                // Sign the transaction message bytes
                const signatureBytes = await this.signBytes(new Uint8Array(transaction.messageBytes));
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Check if AWS KMS is available and the key is accessible
     */
    async isAvailable(): Promise<boolean> {
        try {
            const command = new DescribeKeyCommand({
                KeyId: this.keyId,
            });

            const response = await this.client.send(command);

            if (!response.KeyMetadata) {
                return false;
            }

            // Verify the key spec is ECC_NIST_EDWARDS25519
            const keySpec = response.KeyMetadata.KeySpec;
            const keyUsage = response.KeyMetadata.KeyUsage;
            const keyState = response.KeyMetadata.KeyState;

            return keySpec === 'ECC_NIST_EDWARDS25519' && keyUsage === 'SIGN_VERIFY' && keyState === 'Enabled';
        } catch {
            return false;
        }
    }
}
