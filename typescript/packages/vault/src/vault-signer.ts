import { Address, assertIsAddress } from '@solana/addresses';
import { getBase64Decoder, getBase64Encoder } from '@solana/codecs-strings';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';
import { createSignatureDictionary, SignerErrorCode, SolanaSigner, throwSignerError } from '@solana-keychain/core';

import type {
    VaultErrorResponse,
    VaultKeyReadResponse,
    VaultPayloadBase64,
    VaultSignRequest,
    VaultSignResponse,
} from './types.js';

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
export class VaultSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly vaultAddr: string;
    private readonly vaultToken: string;
    private readonly keyName: string;
    private readonly requestDelayMs: number;

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

        this.vaultAddr = config.vaultAddr.replace(/\/$/, ''); // Remove trailing slash
        this.vaultToken = config.vaultToken;
        this.keyName = config.keyName;
        this.requestDelayMs = config.requestDelayMs || 0;
        this.validateRequestDelayMs(this.requestDelayMs);
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
     * Extract the base64 signature from Vault's response format
     * Vault returns signatures in format: "vault:v1:base64_signature"
     */
    private extractSignatureFromVaultFormat(vaultSignature: string): SignatureBytes {
        // Remove the version prefix if present, otherwise use the signature as-is
        const base64Signature = vaultSignature.startsWith('vault:v1:')
            ? vaultSignature.slice('vault:v1:'.length)
            : vaultSignature;

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

        let response: Response;
        try {
            response = await fetch(url, {
                body: JSON.stringify(request),
                headers: {
                    'Content-Type': 'application/json',
                    'X-Vault-Token': this.vaultToken,
                },
                method: 'POST',
            });
        } catch (error) {
            return throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Vault network request failed',
                url,
            });
        }

        if (!response.ok) {
            let errorMessage = `Vault API error: ${response.status}`;
            try {
                const errorData = (await response.json()) as VaultErrorResponse;
                if (errorData.errors && errorData.errors.length > 0) {
                    errorMessage = `Vault API error: ${errorData.errors.join(', ')}`;
                }
            } catch {
                // Ignore JSON parsing errors for error response
            }

            return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: errorMessage,
                status: response.status,
            });
        }

        let signResponse: VaultSignResponse;
        try {
            signResponse = (await response.json()) as VaultSignResponse;
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Vault signing response',
            });
        }

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

    /**
     * Sign multiple messages using Vault
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                const signatureBytes = await this.signMessageBytes(message.content);
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Sign multiple transactions using Vault
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                // Sign the transaction message bytes
                const signatureBytes = await this.signMessageBytes(transaction.messageBytes);
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
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
