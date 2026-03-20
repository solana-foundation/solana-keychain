import { v1 } from '@google-cloud/kms';
import { Address, assertIsAddress } from '@solana/addresses';
import {
    assertSignatureValid,
    batchSign,
    createBatchDelay,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

import type { GcpKmsSignerConfig } from './types.js';

/**
 * Create a Google Cloud KMS-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createGcpKmsSigner<TAddress extends string = string>(
    config: GcpKmsSignerConfig,
): SolanaSigner<TAddress> {
    return GcpKmsSigner.create(config);
}

/**
 * Google Cloud KMS-based signer using EdDSA (Ed25519) signing
 *
 * The GCP KMS key must be created with:
 * - Algorithm: EC_SIGN_ED25519
 * - Purpose: ASYMMETRIC_SIGN
 *
 * Example gcloud CLI command to create a key:
 * ```bash
 * gcloud kms keys create my-key \
 *   --keyring=my-keyring \
 *   --location=us-east1 \
 *   --purpose=asymmetric-signing \
 *   --default-algorithm=ec-sign-ed25519
 * ```
 *
 * @deprecated Prefer `createGcpKmsSigner()`. Class export will be removed in a future version.
 */
export class GcpKmsSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly keyName: string;
    private readonly client: v1.KeyManagementServiceClient;
    private readonly delay: (index: number) => Promise<void>;

    /** @deprecated Use `createGcpKmsSigner()` instead. */
    static create<TAddress extends string = string>(config: GcpKmsSignerConfig): GcpKmsSigner<TAddress> {
        return new GcpKmsSigner<TAddress>(config);
    }

    /** @deprecated Use `createGcpKmsSigner()` instead. Direct construction will be removed in a future version. */
    constructor(config: GcpKmsSignerConfig) {
        if (!config.keyName) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required keyName field',
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

        this.keyName = config.keyName;
        const requestDelayMs = config.requestDelayMs || 0;
        this.delay = createBatchDelay(requestDelayMs);
        this.client = new v1.KeyManagementServiceClient();
    }

    /**
     * Sign message bytes using GCP KMS EdDSA signing
     */
    private async signBytes(messageBytes: Uint8Array): Promise<SignatureBytes> {
        try {
            // GCP KMS AsymmetricSign expects the raw message for Ed25519 (PureEdDSA)
            const [response] = await this.client.asymmetricSign({
                data: messageBytes,
                name: this.keyName,
            });

            if (!response.signature) {
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    message: 'No signature in GCP KMS response',
                });
            }

            // Ed25519 signatures are 64 bytes
            const signature = response.signature as Uint8Array;
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
                // GCP SDK errors
                const gcpError = error as { code?: number; message?: string };
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    cause: error,
                    message: `GCP KMS Sign operation failed: ${gcpError.message || error.message}`,
                    status: gcpError.code,
                });
            }
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                cause: error,
                message: 'GCP KMS Sign operation failed',
            });
        }
    }

    /**
     * Sign multiple messages using GCP KMS
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: messages,
            signFn: async m => {
                const messageBytes =
                    m.content instanceof Uint8Array ? m.content : new Uint8Array(Array.from(m.content));
                const sig = await this.signBytes(messageBytes);
                await assertSignatureValid({ data: messageBytes, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    /**
     * Sign multiple transactions using GCP KMS
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: transactions,
            signFn: async tx => {
                const txMessageBytes = new Uint8Array(tx.messageBytes);
                const sig = await this.signBytes(txMessageBytes);
                await assertSignatureValid({ data: txMessageBytes, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    /**
     * Check if GCP KMS is available and the key is accessible
     */
    async isAvailable(): Promise<boolean> {
        try {
            const [publicKey] = await this.client.getPublicKey({
                name: this.keyName,
            });

            if (!publicKey) {
                return false;
            }

            // Verify the algorithm is EC_SIGN_ED25519
            return publicKey.algorithm === 'EC_SIGN_ED25519';
        } catch {
            return false;
        }
    }
}
