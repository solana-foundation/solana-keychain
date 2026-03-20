import { Address, assertIsAddress } from '@solana/addresses';
import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertSignatureValid,
    batchSign,
    createBatchDelay,
    fetchWithSignerErrors,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateHttpsUrl,
    validateUrl,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';

import type { VaultKeyReadResponse, VaultPayloadBase64, VaultSignRequest, VaultSignResponse } from './types.js';

/**
 * Create a Vault-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createVaultSigner<TAddress extends string = string>(config: VaultSignerConfig): SolanaSigner<TAddress> {
    return VaultSigner.create(config);
}

/**
 * Configuration for creating a VaultSigner
 */
export interface VaultSignerConfig {
    /** Allow plain HTTP for local development (e.g. Vault dev server on localhost). Default: false. */
    allowHttp?: boolean;
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
 *
 * @deprecated Prefer `createVaultSigner()`. Class export will be removed in a future version.
 */
export class VaultSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly vaultAddr: string;
    private readonly vaultToken: string;
    private readonly keyName: string;
    private readonly delay: (index: number) => Promise<void>;

    /** @deprecated Use `createVaultSigner()` instead. */
    static create<TAddress extends string = string>(config: VaultSignerConfig): VaultSigner<TAddress> {
        return new VaultSigner<TAddress>(config);
    }

    /** @deprecated Use `createVaultSigner()` instead. Direct construction will be removed in a future version. */
    constructor(config: VaultSignerConfig) {
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

        const vaultAddr = config.vaultAddr.replace(/\/$/, ''); // Remove trailing slash
        if (config.allowHttp) {
            validateUrl(vaultAddr, 'vaultAddr');
        } else {
            validateHttpsUrl(vaultAddr, 'vaultAddr');
        }

        this.vaultAddr = vaultAddr;
        this.vaultToken = config.vaultToken;
        this.keyName = config.keyName;
        const requestDelayMs = config.requestDelayMs || 0;
        this.delay = createBatchDelay(requestDelayMs);
    }

    /**
     * Extract the base64 signature from Vault's response format
     * Vault returns signatures in format: "vault:vN:base64_signature"
     */
    private extractSignatureFromVaultFormat(vaultSignature: string): SignatureBytes {
        // Remove any Vault version prefix (vault:v1:, vault:v2:, ...)
        const base64Signature = vaultSignature.replace(/^vault:v\d+:/, '');

        if (!base64Signature) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: `Empty signature in Vault response`,
            });
        }

        // Decode base64 string to Uint8Array (SignatureBytes)
        const encoder = getBase64Encoder();
        return encoder.encode(base64Signature) as SignatureBytes;
    }

    /**
     * Sign data using Vault's transit engine
     */
    private async signWithVault(base64Data: string): Promise<SignatureBytes> {
        const url = `${this.vaultAddr}/v1/transit/sign/${this.keyName}`;

        const request: VaultSignRequest = {
            input: base64Data as VaultPayloadBase64,
        };

        const signResponse = await fetchWithSignerErrors<VaultSignResponse>(
            url,
            {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-Vault-Token': this.vaultToken,
                },
                method: 'POST',
            },
            'Vault',
        );

        if (!signResponse.data?.signature) {
            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature in Vault response',
            });
        }

        return this.extractSignatureFromVaultFormat(signResponse.data.signature);
    }

    /**
     * Sign message bytes using Vault
     */
    private async signMessageBytes(messageBytes: ArrayLike<number>): Promise<SignatureBytes> {
        // Encode message bytes to base64 string for Vault
        const decoder = getBase64Decoder();
        const bytes = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(Array.from(messageBytes));
        const base64EncodedMessage = decoder.decode(bytes);
        return await this.signWithVault(base64EncodedMessage);
    }

    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: messages,
            signFn: async m => {
                const sig = await this.signMessageBytes(m.content);
                await assertSignatureValid({ data: m.content, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await batchSign({
            delay: this.delay,
            items: transactions,
            signFn: async t => {
                const sig = await this.signMessageBytes(t.messageBytes);
                await assertSignatureValid({ data: t.messageBytes, signature: sig, signerAddress: this.address });
                return sig;
            },
            signerAddress: this.address,
        });
    }

    /**
     * Check if the Vault signer is available by attempting to read key metadata
     */
    async isAvailable(): Promise<boolean> {
        const url = `${this.vaultAddr}/v1/transit/keys/${this.keyName}`;

        try {
            const response = await fetch(url, {
                headers: {
                    'X-Vault-Token': this.vaultToken,
                },
                method: 'GET',
            });

            if (!response.ok) {
                return false;
            }

            const keyData = (await response.json()) as VaultKeyReadResponse;
            return keyData.data?.supports_signing === true && keyData.data?.type === 'ed25519';
        } catch {
            return false;
        }
    }
}
