import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase64Encoder } from '@solana/codecs-strings';
import { createSignatureDictionary, SignerErrorCode, SolanaSigner, throwSignerError } from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getBase64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import { ApiKeyStamper } from './stamper.js';
import type { ActivityResponse, SignRequest, SignTransactionRequest, WhoAmIRequest, WhoAmIResponse } from './types.js';

/**
 * Configuration for creating a TurnkeySigner
 */
export interface TurnkeySignerConfig {
    /** Optional custom API base URL (defaults to https://api.turnkey.com) */
    apiBaseUrl?: string;
    /** Turnkey API private key (hex-encoded) for P256 authentication */
    apiPrivateKey: string;
    /** Turnkey API public key (hex-encoded) */
    apiPublicKey: string;
    /** Turnkey organization ID */
    organizationId: string;
    /** Turnkey private key ID to use for signing Solana transactions */
    privateKeyId: string;
    /** Solana public key (base58) corresponding to the private key ID */
    publicKey: string;
    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;
}

/**
 * Turnkey-based signer using Turnkey's API
 *
 * Uses P256 ECDSA for API authentication (X-Stamp header) and Ed25519 for Solana signing
 */
export class TurnkeySigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiBaseUrl: string;
    private readonly organizationId: string;
    private readonly privateKeyId: string;
    private readonly stamper: ApiKeyStamper;
    private readonly requestDelayMs: number;

    constructor(config: TurnkeySignerConfig) {
        if (!config.apiPublicKey || !config.apiPrivateKey || !config.organizationId || !config.privateKeyId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message:
                    'Missing required configuration fields (apiPublicKey, apiPrivateKey, organizationId, or privateKeyId)',
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

        this.organizationId = config.organizationId;
        this.privateKeyId = config.privateKeyId;
        this.apiBaseUrl = config.apiBaseUrl || 'https://api.turnkey.com';
        this.stamper = new ApiKeyStamper({
            apiPrivateKey: config.apiPrivateKey,
            apiPublicKey: config.apiPublicKey,
        });
        this.requestDelayMs = config.requestDelayMs || 0;
        this.validateRequestDelayMs(this.requestDelayMs);
    }

    /**
     * Validate request delay ms
     * @param requestDelayMs
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
     * Delay between concurrent signing requests to avoid rate limits
     * @param index
     */
    private async delay(index: number): Promise<void> {
        if (this.requestDelayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * this.requestDelayMs));
        }
    }

    /**
     * Pad signature component to exactly 32 bytes
     * Components from Turnkey may be shorter than 32 bytes and need left-padding with zeros
     */
    private padSignatureComponent(hex: string): Uint8Array {
        const hexToBytes = getBase16Encoder().encode;
        const bytes = hexToBytes(hex);

        if (bytes.length > 32) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature component length: ${bytes.length} (max 32)`,
            });
        }

        // Create 32-byte array and right-align the component (left-pad with zeros)
        const padded = new Uint8Array(32);
        padded.set(bytes, 32 - bytes.length);
        return padded;
    }

    /**
     * Sign a hex-encoded payload using Turnkey API
     * (sign_raw_payload - https://docs.turnkey.com/api-reference/activities/sign-raw-payload)
     *
     * @param hexPayload
     * @returns Promise of SignatureBytes
     */
    private async sign(hexPayload: string): Promise<SignatureBytes> {
        const timestampMs = Date.now().toString();

        const request: SignRequest = {
            organizationId: this.organizationId,
            parameters: {
                encoding: 'PAYLOAD_ENCODING_HEXADECIMAL',
                hashFunction: 'HASH_FUNCTION_NOT_APPLICABLE',
                payload: hexPayload,
                signWith: this.privateKeyId,
            },
            timestampMs,
            type: 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2',
        };

        const body = JSON.stringify(request);
        const stamp = this.stamper.stamp(body);

        const url = `${this.apiBaseUrl}/public/v1/submit/sign_raw_payload`;

        let response: Response;
        try {
            response = await fetch(url, {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    [stamp.stampHeaderName]: stamp.stampHeaderValue,
                },
                method: 'POST',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Turnkey network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Turnkey API error: ${response.status}`,
                response: errorText,
                status: response.status,
            });
        }

        let activityResponse: ActivityResponse;
        try {
            activityResponse = (await response.json()) as ActivityResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Turnkey response',
            });
        }

        const signResult = activityResponse.activity.result?.signRawPayloadResult;
        if (!signResult || !signResult.r || !signResult.s) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature components in Turnkey response',
            });
        }

        // Pad r and s components to exactly 32 bytes each
        const rPadded = this.padSignatureComponent(signResult.r);
        const sPadded = this.padSignatureComponent(signResult.s);

        // Combine into 64-byte signature
        const signature = new Uint8Array(64);
        signature.set(rPadded, 0);
        signature.set(sPadded, 32);

        return signature as SignatureBytes;
    }

    /**
     * Sign multiple messages using Turnkey API
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            messages.map(async (message, index) => {
                await this.delay(index);
                // Convert message bytes to hex for Turnkey
                const bytesToHex = getBase16Decoder().decode;
                const hexMessage = bytesToHex(message.content);
                const signatureBytes = await this.sign(hexMessage);
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Sign a transaction using Turnkey's sign_transaction endpoint
     * (sign_transaction - https://docs.turnkey.com/api-reference/activities/sign-transaction)
     *
     * @param hexTransaction
     * @returns Promise of string (signed transaction hex)
     */
    private async signTransaction(hexTransaction: string): Promise<string> {
        const timestampMs = Date.now().toString();

        const request: SignTransactionRequest = {
            organizationId: this.organizationId,
            parameters: {
                signWith: this.privateKeyId,
                type: 'TRANSACTION_TYPE_SOLANA',
                unsignedTransaction: hexTransaction,
            },
            timestampMs,
            type: 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2',
        };

        const body = JSON.stringify(request);
        const stamp = this.stamper.stamp(body);

        const url = `${this.apiBaseUrl}/public/v1/submit/sign_transaction`;

        let response: Response;
        try {
            response = await fetch(url, {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    [stamp.stampHeaderName]: stamp.stampHeaderValue,
                },
                method: 'POST',
            });
        } catch (error) {
            throwSignerError(SignerErrorCode.HTTP_ERROR, {
                cause: error,
                message: 'Turnkey network request failed',
                url,
            });
        }

        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Turnkey API error: ${response.status}`,
                response: errorText,
                status: response.status,
            });
        }

        let activityResponse: ActivityResponse;
        try {
            activityResponse = (await response.json()) as ActivityResponse;
        } catch (error) {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to parse Turnkey response',
            });
        }

        const signedTransaction = activityResponse.activity.result?.signTransactionResult?.signedTransaction;
        if (!signedTransaction) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signedTransaction in Turnkey response',
            });
        }

        return signedTransaction;
    }

    /**
     * Sign multiple transactions using Turnkey API
     *
     * @param transactions
     * @returns Promise of readonly SignatureDictionary[]
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        return await Promise.all(
            transactions.map(async (transaction, index) => {
                await this.delay(index);
                const wireTransaction = getBase64EncodedWireTransaction(transaction);

                // Convert base64 wire transaction to bytes, then to hex for Turnkey
                const base64ToBytes = getBase64Encoder().encode;
                const txBytes = base64ToBytes(wireTransaction);
                const bytesToHex = getBase16Decoder().decode;
                const hexTx = bytesToHex(txBytes as Uint8Array);

                // Use Turnkey's sign_transaction endpoint which returns the full signed transaction
                const signedTransactionHex = await this.signTransaction(hexTx);

                // Convert signed transaction hex back to bytes
                const hexToBytes = getBase16Encoder().encode;
                const signedTxBytes = hexToBytes(signedTransactionHex);

                // Extract the signature from the signed transaction
                // In Solana, signatures are at the beginning of the serialized transaction
                // First byte is the signature count, then 64 bytes per signature
                const signature = signedTxBytes.slice(1, 65) as SignatureBytes;

                // Create a signature dictionary from the extracted signature
                return createSignatureDictionary({
                    signature,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Check if the Turnkey signer is available
     *
     * @returns Promise of boolean
     */
    async isAvailable(): Promise<boolean> {
        try {
            const request: WhoAmIRequest = {
                organizationId: this.organizationId,
            };
            const body = JSON.stringify(request);
            const stamp = this.stamper.stamp(body);
            const url = `${this.apiBaseUrl}/public/v1/query/whoami`;

            const response = await fetch(url, {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    [stamp.stampHeaderName]: stamp.stampHeaderValue,
                },
                method: 'POST',
            });
            if (!response.ok) {
                return false;
            }

            const whoami = (await response.json()) as WhoAmIResponse;

            return whoami.organizationId === this.organizationId;
        } catch {
            return false;
        }
    }
}
