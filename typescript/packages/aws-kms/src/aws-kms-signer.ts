import { DescribeKeyCommand, KMSClient, MessageType, SignCommand, SigningAlgorithmSpec } from '@aws-sdk/client-kms';
import { Address, assertIsAddress } from '@solana/addresses';
import {
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    signBatchStaggered,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import {
    MessagePartialSignerConfig,
    SignableMessage,
    SignatureDictionary,
    TransactionPartialSignerConfig,
} from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

import type { AwsCredentials, AwsKmsSignerConfig } from './types.js';

/**
 * Create an AWS KMS-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createAwsKmsSigner<TAddress extends string = string>(
    config: AwsKmsSignerConfig,
): SolanaSigner<TAddress> {
    return AwsKmsSigner.create(config);
}

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
class AwsKmsSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly keyId: string;
    private readonly client: KMSClient;
    private readonly requestDelayMs: number;

    static create<TAddress extends string = string>(config: AwsKmsSignerConfig): AwsKmsSigner<TAddress> {
        return new AwsKmsSigner<TAddress>(config);
    }

    private constructor(config: AwsKmsSignerConfig) {
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
        validateRequestDelayMs(this.requestDelayMs);

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
     * Sign message bytes using AWS KMS EdDSA signing
     */
    private async signBytes(messageBytes: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        try {
            const command = new SignCommand({
                KeyId: this.keyId,
                Message: messageBytes,
                MessageType: MessageType.RAW,
                SigningAlgorithm: SigningAlgorithmSpec.ED25519_SHA_512,
            });

            const response = await this.client.send(command, { abortSignal });

            if (!response.Signature) {
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    message: 'No signature in AWS KMS response',
                });
            }

            const signature = new Uint8Array(response.Signature);
            if (signature.length !== ED25519_SIGNATURE_LENGTH) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${signature.length}`,
                });
            }

            return signature as SignatureBytes;
        } catch (error: unknown) {
            abortSignal?.throwIfAborted();
            if (error instanceof Error && error.name === 'SignerError') {
                throw error;
            }
            if (error instanceof Error) {
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
    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signBytes(messageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: messageBytes,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Sign multiple transactions using AWS KMS
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const txMessageBytes = new Uint8Array(transaction.messageBytes);
                const signatureBytes = await this.signBytes(txMessageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: txMessageBytes,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            },
            this.requestDelayMs,
            config?.abortSignal,
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

            const keySpec = response.KeyMetadata.KeySpec;
            const keyUsage = response.KeyMetadata.KeyUsage;
            const keyState = response.KeyMetadata.KeyState;

            return keySpec === 'ECC_NIST_EDWARDS25519' && keyUsage === 'SIGN_VERIFY' && keyState === 'Enabled';
        } catch {
            return false;
        }
    }
}
