import { Address, assertIsAddress } from '@solana/addresses';
import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    normalizeMessageBytes,
    signBatchStaggered,
    SignerErrorCode,
    SolanaMessageSigner,
    SolanaTransactionSigner,
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
import { GoogleAuth } from 'google-auth-library';

import type { GcpKmsSignerConfig } from './types.js';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;

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
): SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress> {
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
 */
class GcpKmsSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;
    private readonly keyName: string;
    private readonly keyNamePathSegments: readonly string[];
    private readonly auth: GoogleAuth;
    private readonly requestDelayMs: number;

    static create<TAddress extends string = string>(config: GcpKmsSignerConfig): GcpKmsSigner<TAddress> {
        return new GcpKmsSigner<TAddress>(config);
    }

    private constructor(config: GcpKmsSignerConfig) {
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

    private async request<TResponse>(url: string, init: RequestInit, abortSignal?: AbortSignal): Promise<TResponse> {
        const headers = await this.buildAuthorizedHeaders(url, init);
        return await fetchSignerJson<TResponse>({
            abortSignal,
            init: { ...init, headers },
            providerName: 'GCP KMS',
            url,
        });
    }

    /**
     * Sign message bytes using GCP KMS EdDSA signing
     */
    private async signBytes(messageBytes: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        base64Decoder ||= getBase64Decoder();
        try {
            const response = await this.request<AsymmetricSignResponse>(
                this.buildResourceUrl(':asymmetricSign'),
                {
                    body: JSON.stringify({
                        data: base64Decoder.decode(messageBytes),
                    }),
                    method: 'POST',
                },
                abortSignal,
            );

            if (!response.signature) {
                throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                    message: 'No signature in GCP KMS response',
                });
            }

            base64Encoder ||= getBase64Encoder();
            const signature = new Uint8Array(base64Encoder.encode(response.signature));
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
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'GCP KMS Sign operation failed',
            });
        }
    }

    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes = normalizeMessageBytes(message.content);
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

    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const txMessageBytes = normalizeMessageBytes(transaction.messageBytes);
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

            return publicKey.algorithm === 'EC_SIGN_ED25519';
        } catch {
            return false;
        }
    }
}
