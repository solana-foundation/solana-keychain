import { Address, assertIsAddress } from '@solana/addresses';
import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    normalizeBaseUrl,
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

import type { VaultKeyReadResponse, VaultPayloadBase64, VaultSignRequest, VaultSignResponse } from './types.js';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;

/**
 * Create a Vault-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createVaultSigner<TAddress extends string = string>(
    config: VaultSignerConfig,
): SolanaMessageSigner<TAddress> & SolanaTransactionSigner<TAddress> {
    return VaultSigner.create(config);
}

/**
 * Configuration for creating a VaultSigner
 */
export interface VaultSignerConfig {
    /** Name of the transit key in Vault */
    keyName: string;
    /** Solana public key (base58) corresponding to the Vault key */
    publicKey: string;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
    /** Vault server address (e.g., https://vault.example.com) */
    vaultAddr: string;
    /** Vault authentication token */
    vaultToken: string;
}

/**
 * HashiCorp Vault-based signer using Vault's transit engine
 *
 * The Vault key must be an ED25519 key created in the transit engine.
 * Example creation: `vault write transit/keys/my-key type=ed25519`
 */
class VaultSigner<TAddress extends string = string>
    implements SolanaMessageSigner<TAddress>, SolanaTransactionSigner<TAddress>
{
    readonly address: Address<TAddress>;
    private readonly vaultAddr: string;
    private readonly vaultToken: string;
    private readonly keyName: string;
    private readonly requestDelayMs: number;

    static create<TAddress extends string = string>(config: VaultSignerConfig): VaultSigner<TAddress> {
        return new VaultSigner<TAddress>(config);
    }

    private constructor(config: VaultSignerConfig) {
        if (!config.vaultAddr || !config.vaultToken || !config.keyName) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required configuration fields (vaultAddr, vaultToken, or keyName)',
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

        const vaultAddr = normalizeBaseUrl(config.vaultAddr);
        assertHttpsUrl(vaultAddr, 'vaultAddr', { allowHttpLoopbackInTests: true });

        this.vaultAddr = vaultAddr;
        this.vaultToken = config.vaultToken;
        this.keyName = config.keyName;
        this.requestDelayMs = config.requestDelayMs || 0;
        validateRequestDelayMs(this.requestDelayMs);
    }

    /**
     * Extract the base64 signature from Vault's response format
     * Vault returns signatures in format: "vault:vN:base64_signature"
     */
    private extractSignatureFromVaultFormat(vaultSignature: string): SignatureBytes {
        const base64Signature = vaultSignature.replace(/^vault:v\d+:/, '');

        if (!base64Signature) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: `Empty signature in Vault response`,
            });
        }

        let sigBytes: Uint8Array;
        try {
            base64Encoder ||= getBase64Encoder();
            sigBytes = new Uint8Array(base64Encoder.encode(base64Signature));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Vault signature base64',
            });
        }
        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${sigBytes.length}`,
            });
        }
        return sigBytes as SignatureBytes;
    }

    private async signWithVault(base64Data: string, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        const url = `${this.vaultAddr}/v1/transit/sign/${encodeURIComponent(this.keyName)}`;

        const request: VaultSignRequest = {
            input: base64Data as VaultPayloadBase64,
        };

        const signResponse = await fetchSignerJson<VaultSignResponse>({
            abortSignal,
            init: {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-Vault-Token': this.vaultToken,
                },
                method: 'POST',
            },
            providerName: 'Vault',
            url,
        });

        if (!signResponse.data?.signature) {
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Vault response',
            });
        }

        return this.extractSignatureFromVaultFormat(signResponse.data.signature);
    }

    private async signMessageBytes(
        messageBytes: ArrayLike<number>,
        abortSignal?: AbortSignal,
    ): Promise<SignatureBytes> {
        base64Decoder ||= getBase64Decoder();
        const bytes = normalizeMessageBytes(messageBytes);
        const base64EncodedMessage = base64Decoder.decode(bytes);
        return await this.signWithVault(base64EncodedMessage, abortSignal);
    }

    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const signatureBytes = await this.signMessageBytes(message.content, config?.abortSignal);
                await assertSignatureValid({
                    data: message.content,
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
                const signatureBytes = await this.signMessageBytes(transaction.messageBytes, config?.abortSignal);
                await assertSignatureValid({
                    data: transaction.messageBytes,
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
     * Check if the Vault signer is available by attempting to read key metadata
     */
    async isAvailable(): Promise<boolean> {
        const url = `${this.vaultAddr}/v1/transit/keys/${encodeURIComponent(this.keyName)}`;

        try {
            const keyData = await fetchSignerJson<VaultKeyReadResponse>({
                init: {
                    headers: {
                        'X-Vault-Token': this.vaultToken,
                    },
                    method: 'GET',
                },
                providerName: 'Vault',
                url,
            });
            return keyData.data?.supports_signing === true && keyData.data?.type === 'ed25519';
        } catch {
            return false;
        }
    }
}
