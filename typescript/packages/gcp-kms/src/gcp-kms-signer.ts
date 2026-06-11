import { Address, assertIsAddress } from '@solana/addresses';
import {
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    signBatchStaggered,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';
import { GoogleAuth } from 'google-auth-library';

import type { GcpKmsSignerConfig } from './types.js';

/**
 * Create a Google Cloud KMS-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
const CLOUD_KMS_BASE_URL = 'https://cloudkms.googleapis.com/v1';
const CLOUD_KMS_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const GCP_KMS_KEY_NAME_PATTERN =
    /^projects\/[A-Za-z0-9._-]+\/locations\/[A-Za-z0-9._-]+\/keyRings\/[A-Za-z0-9._-]+\/cryptoKeys\/[A-Za-z0-9._-]+\/cryptoKeyVersions\/[A-Za-z0-9._-]+$/;

type AsymmetricSignResponse = {
    signature?: string;
};

type PublicKeyResponse = {
    algorithm?: string;
};
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
    private readonly keyNamePathSegments: readonly string[];
    private readonly auth: GoogleAuth;
    private readonly requestDelayMs: number;

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

        this.keyName = this.normalizeKeyName(config.keyName);
        this.keyNamePathSegments = this.keyName.split('/');
        this.requestDelayMs = config.requestDelayMs || 0;
        validateRequestDelayMs(this.requestDelayMs);
        this.auth = new GoogleAuth({ scopes: [CLOUD_KMS_SCOPE] });
    }

    private normalizeKeyName(keyName: string): string {
        const canonicalKeyName = keyName.replace(/^\/+/, '');

        if (/\/{2,}/.test(canonicalKeyName) || /[#?%]/.test(canonicalKeyName)) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Invalid GCP KMS keyName format',
            });
        }

        if (!GCP_KMS_KEY_NAME_PATTERN.test(canonicalKeyName)) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Invalid GCP KMS keyName format',
            });
        }

        return canonicalKeyName;
    }

    private buildResourceUrl(suffix: ':asymmetricSign' | '/publicKey'): string {
        const url = new URL(`${CLOUD_KMS_BASE_URL}/`);
        const basePathSegments = url.pathname.split('/').filter(Boolean);
        url.pathname = `/${[...basePathSegments, ...this.keyNamePathSegments].join('/')}${suffix}`;
        return url.toString();
    }

    private async buildAuthorizedHeaders(url: string, init: RequestInit): Promise<Headers> {
        const authHeaders = await this.auth.getRequestHeaders(url);
        const headers = new Headers(init.headers);

        authHeaders.forEach((value, key) => {
            headers.set(key, value);
        });

        if (init.body && !headers.has('content-type')) {
            headers.set('content-type', 'application/json');
        }

        return headers;
    }

    private async request<TResponse>(url: string, init: RequestInit): Promise<TResponse> {
        const headers = await this.buildAuthorizedHeaders(url, init);
        return await fetchSignerJson<TResponse>({
            init: { ...init, headers },
            providerName: 'GCP KMS',
            url,
        });
    }

    /**
     * Sign message bytes using GCP KMS EdDSA signing
     */
    private async signBytes(messageBytes: Uint8Array): Promise<SignatureBytes> {
        try {
            const response = await this.request<AsymmetricSignResponse>(this.buildResourceUrl(':asymmetricSign'), {
                body: JSON.stringify({
                    data: Buffer.from(messageBytes).toString('base64'),
                }),
                method: 'POST',
            });

            if (!response.signature) {
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    message: 'No signature in GCP KMS response',
                });
            }

            // Ed25519 signatures are 64 bytes
            const signature = new Uint8Array(Buffer.from(response.signature, 'base64'));
            if (signature.length !== ED25519_SIGNATURE_LENGTH) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${signature.length}`,
                });
            }

            return signature as SignatureBytes;
        } catch (error: unknown) {
            // Re-throw SignerError as-is (from request())
            if (error instanceof Error && error.name === 'SignerError') {
                throw error;
            }
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'GCP KMS Sign operation failed',
            });
        }
    }

    /**
     * Sign multiple messages using GCP KMS
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.signBytes(messageBytes);
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
        );
    }

    /**
     * Sign multiple transactions using GCP KMS
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                // Sign the transaction message bytes
                const txMessageBytes = new Uint8Array(transaction.messageBytes);
                const signatureBytes = await this.signBytes(txMessageBytes);
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
        );
    }

    /**
     * Check if GCP KMS is available and the key is accessible
     */
    async isAvailable(): Promise<boolean> {
        try {
            const publicKey = await this.request<PublicKeyResponse>(this.buildResourceUrl('/publicKey'), {
                method: 'GET',
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
