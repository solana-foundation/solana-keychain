import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase64Encoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    extractSignatureFromTransactionBytes,
    fetchSignerJson,
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
import {
    getBase64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import { ApiKeyStamper } from './stamper.js';
import type { ActivityResponse, SignRequest, SignTransactionRequest, WhoAmIRequest, WhoAmIResponse } from './types.js';

/**
 * Create a Turnkey-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export function createTurnkeySigner<TAddress extends string = string>(
    config: TurnkeySignerConfig,
): SolanaSigner<TAddress> {
    return TurnkeySigner.create(config);
}

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
class TurnkeySigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly apiBaseUrl: string;
    private readonly organizationId: string;
    private readonly privateKeyId: string;
    private readonly stamper: ApiKeyStamper;
    private readonly requestDelayMs: number;

    static create<TAddress extends string = string>(config: TurnkeySignerConfig): TurnkeySigner<TAddress> {
        return new TurnkeySigner<TAddress>(config);
    }

    private constructor(config: TurnkeySignerConfig) {
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
        const apiBaseUrl = config.apiBaseUrl || 'https://api.turnkey.com';
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

        this.apiBaseUrl = apiBaseUrl;
        this.stamper = new ApiKeyStamper({
            apiPrivateKey: config.apiPrivateKey,
            apiPublicKey: config.apiPublicKey,
        });
        this.requestDelayMs = config.requestDelayMs || 0;
        validateRequestDelayMs(this.requestDelayMs);
    }

    /**
     * Reject activity responses that have not completed.
     *
     * Turnkey executes activities optimistically and populates `result` only once
     * the activity reaches `ACTIVITY_STATUS_COMPLETED`; anything else (e.g.
     * `ACTIVITY_STATUS_CONSENSUS_NEEDED` under a quorum policy) carries no signature.
     */
    private assertActivityCompleted(activityResponse: ActivityResponse): void {
        const status = activityResponse.activity?.status;
        if (status !== 'ACTIVITY_STATUS_COMPLETED') {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Turnkey activity is not completed (status: ${status || '<missing>'})`,
            });
        }
    }

    /**
     * Pad signature component to exactly 32 bytes
     * Components from Turnkey may be shorter than 32 bytes and need left-padding with zeros
     */
    private padSignatureComponent(hex: string): Uint8Array {
        if (hex.length % 2 !== 0) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Invalid signature component from Turnkey API: odd-length hex string (${hex.length} chars)`,
            });
        }
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
    private async sign(hexPayload: string, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        const request: SignRequest = {
            organizationId: this.organizationId,
            parameters: {
                encoding: 'PAYLOAD_ENCODING_HEXADECIMAL',
                hashFunction: 'HASH_FUNCTION_NOT_APPLICABLE',
                payload: hexPayload,
                signWith: this.privateKeyId,
            },
            timestampMs: Date.now().toString(),
            type: 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2',
        };

        const body = JSON.stringify(request);
        const stamp = this.stamper.stamp(body);

        const activityResponse = await fetchSignerJson<ActivityResponse>({
            abortSignal,
            init: {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    [stamp.stampHeaderName]: stamp.stampHeaderValue,
                },
                method: 'POST',
            },
            providerName: 'Turnkey',
            url: `${this.apiBaseUrl}/public/v1/submit/sign_raw_payload`,
        });

        this.assertActivityCompleted(activityResponse);

        const signResult = activityResponse.activity?.result?.signRawPayloadResult;
        if (!signResult || !signResult.r || !signResult.s) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'Missing signature components in Turnkey response',
            });
        }

        const rPadded = this.padSignatureComponent(signResult.r);
        const sPadded = this.padSignatureComponent(signResult.s);

        const signature = new Uint8Array(ED25519_SIGNATURE_LENGTH);
        signature.set(rPadded, 0);
        signature.set(sPadded, ED25519_SIGNATURE_LENGTH / 2);

        return signature as SignatureBytes;
    }

    /**
     * Sign multiple messages using Turnkey API
     */
    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const bytesToHex = getBase16Decoder().decode;
                const hexMessage = bytesToHex(message.content);
                const signatureBytes = await this.sign(hexMessage, config?.abortSignal);
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

    /**
     * Sign a transaction using Turnkey's sign_transaction endpoint
     * (sign_transaction - https://docs.turnkey.com/api-reference/activities/sign-transaction)
     *
     * @param hexTransaction
     * @returns Promise of string (signed transaction hex)
     */
    private async signTransaction(hexTransaction: string, abortSignal?: AbortSignal): Promise<string> {
        const request: SignTransactionRequest = {
            organizationId: this.organizationId,
            parameters: {
                signWith: this.privateKeyId,
                type: 'TRANSACTION_TYPE_SOLANA',
                unsignedTransaction: hexTransaction,
            },
            timestampMs: Date.now().toString(),
            type: 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2',
        };

        const body = JSON.stringify(request);
        const stamp = this.stamper.stamp(body);

        const activityResponse = await fetchSignerJson<ActivityResponse>({
            abortSignal,
            init: {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    [stamp.stampHeaderName]: stamp.stampHeaderValue,
                },
                method: 'POST',
            },
            providerName: 'Turnkey',
            url: `${this.apiBaseUrl}/public/v1/submit/sign_transaction`,
        });

        this.assertActivityCompleted(activityResponse);

        const signedTransaction = activityResponse.activity?.result?.signTransactionResult?.signedTransaction;
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
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const wireTransaction = getBase64EncodedWireTransaction(transaction);

                const base64ToBytes = getBase64Encoder().encode;
                const txBytes = base64ToBytes(wireTransaction);
                const bytesToHex = getBase16Decoder().decode;
                const hexTx = bytesToHex(txBytes);

                const signedTransactionHex = await this.signTransaction(hexTx, config?.abortSignal);

                const hexToBytes = getBase16Encoder().encode;
                const signedTxBytes = hexToBytes(signedTransactionHex);
                const sigDict = extractSignatureFromTransactionBytes({
                    signerAddress: this.address,
                    transactionBytes: signedTxBytes,
                });
                await assertSignatureValid({
                    data: transaction.messageBytes,
                    signature: sigDict[this.address],
                    signerAddress: this.address,
                });
                return sigDict;
            },
            this.requestDelayMs,
            config?.abortSignal,
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

            const whoami = await fetchSignerJson<WhoAmIResponse>({
                init: {
                    body,
                    headers: {
                        'Content-Type': 'application/json',
                        [stamp.stampHeaderName]: stamp.stampHeaderValue,
                    },
                    method: 'POST',
                },
                providerName: 'Turnkey',
                url: `${this.apiBaseUrl}/public/v1/query/whoami`,
            });

            return whoami?.organizationId === this.organizationId;
        } catch {
            return false;
        }
    }
}
