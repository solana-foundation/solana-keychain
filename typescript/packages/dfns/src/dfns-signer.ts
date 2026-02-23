import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase58Decoder } from '@solana/codecs-strings';
import { createSignatureDictionary, SignerErrorCode, SolanaSigner, throwSignerError } from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getTransactionEncoder,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import { signUserAction } from './auth.js';
import type {
    DfnsSignerConfig,
    GenerateSignatureRequest,
    GenerateSignatureResponse,
    GetWalletResponse,
} from './types.js';

const DEFAULT_API_BASE_URL = 'https://api.dfns.io';

const base16Encoder = getBase16Encoder();
const base16Decoder = getBase16Decoder();
const base58Decoder = getBase58Decoder();

function hexToBytes(hex: string): Uint8Array {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    return new Uint8Array(base16Encoder.encode(clean));
}

function bytesToHex(bytes: Uint8Array): string {
    return base16Decoder.decode(bytes);
}
function bytesToBase58(bytes: Uint8Array): string {
    return base58Decoder.decode(bytes);
}

/**
 * Dfns-based signer for Solana transactions
 *
 * Uses Dfns Keys API to sign Solana transactions and messages.
 * Requires a Dfns account with a Solana wallet.
 *
 * @example
 * ```typescript
 * const signer = new DfnsSigner({
 *   authToken: 'your-service-account-token',
 *   credId: 'your-credential-id',
 *   privateKeyPem: '-----BEGIN PRIVATE KEY-----\n...',
 *   walletId: 'your-wallet-id',
 * });
 * await signer.init();
 * ```
 */
export class DfnsSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    private _address: Address<TAddress> | null = null;
    private readonly authToken: string;
    private readonly credId: string;
    private readonly privateKeyPem: string;
    private readonly walletId: string;
    private readonly apiBaseUrl: string;
    private keyId = '';
    private initialized = false;

    constructor(config: DfnsSignerConfig) {
        if (!config.authToken) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required authToken field',
            });
        }

        if (!config.credId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required credId field',
            });
        }

        if (!config.privateKeyPem) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required privateKeyPem field',
            });
        }

        if (!config.walletId) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'Missing required walletId field',
            });
        }

        this.authToken = config.authToken;
        this.credId = config.credId;
        this.privateKeyPem = config.privateKeyPem;
        this.walletId = config.walletId;
        this.apiBaseUrl = config.apiBaseUrl ?? DEFAULT_API_BASE_URL;
    }

    /**
     * Get the public key address of this signer
     * @throws {SignerError} If the signer has not been initialized
     */
    get address(): Address<TAddress> {
        if (!this._address) {
            throwSignerError(SignerErrorCode.SIGNER_NOT_INITIALIZED, {
                message: 'Signer not initialized. Call init() first.',
            });
        }
        return this._address;
    }

    /**
     * Initialize the signer by fetching the wallet and extracting key details from Dfns
     */
    async init(): Promise<void> {
        if (this.initialized) {
            return;
        }

        const wallet = await this.getWallet();

        if (wallet.status !== 'Active') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Wallet is not active: ${wallet.status}`,
            });
        }

        if (wallet.signingKey.scheme !== 'EdDSA') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unsupported key scheme: ${wallet.signingKey.scheme} (expected EdDSA)`,
            });
        }

        if (wallet.signingKey.curve !== 'ed25519') {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Unsupported key curve: ${wallet.signingKey.curve} (expected ed25519)`,
            });
        }

        const pubkeyBytes = hexToBytes(wallet.signingKey.publicKey);
        const bs58Address = bytesToBase58(pubkeyBytes);

        try {
            assertIsAddress(bs58Address);
            this._address = bs58Address as Address<TAddress>;
        } catch {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                message: 'Invalid public key from Dfns wallet',
            });
        }

        this.keyId = wallet.signingKey.id;
        this.initialized = true;
    }

    /**
     * Sign multiple messages using Dfns
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await Promise.all(
            messages.map(async message => {
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.sendSignatureRequest({
                    kind: 'Message',
                    message: `0x${bytesToHex(messageBytes)}`,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Sign multiple transactions using Dfns
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        this.ensureInitialized();

        return await Promise.all(
            transactions.map(async transaction => {
                const txEncoder = getTransactionEncoder();
                const txBytes = txEncoder.encode(transaction);
                const signatureBytes = await this.sendSignatureRequest({
                    blockchainKind: 'Solana',
                    kind: 'Transaction',
                    transaction: `0x${bytesToHex(new Uint8Array(txBytes))}`,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            }),
        );
    }

    /**
     * Check if Dfns API is available
     */
    async isAvailable(): Promise<boolean> {
        try {
            await this.getWallet();
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Fetch wallet details from Dfns
     */
    private async getWallet(): Promise<GetWalletResponse> {
        const url = `${this.apiBaseUrl}/wallets/${this.walletId}`;
        const response = await fetch(url, {
            headers: {
                Authorization: `Bearer ${this.authToken}`,
            },
            method: 'GET',
        });

        if (!response.ok) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Dfns API error: ${response.status}`,
                status: response.status,
            });
        }

        try {
            return (await response.json()) as GetWalletResponse;
        } catch {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Failed to parse Dfns wallet response',
            });
        }
    }

    /**
     * Send a signature request to the Dfns Keys API
     */
    private async sendSignatureRequest(request: GenerateSignatureRequest): Promise<SignatureBytes> {
        const httpPath = `/keys/${this.keyId}/signatures`;
        const requestBody = JSON.stringify(request);

        const userAction = await signUserAction(
            this.apiBaseUrl,
            this.authToken,
            this.credId,
            this.privateKeyPem,
            'POST',
            httpPath,
            requestBody,
        );

        const url = `${this.apiBaseUrl}${httpPath}`;
        const response = await fetch(url, {
            body: requestBody,
            headers: {
                Authorization: `Bearer ${this.authToken}`,
                'Content-Type': 'application/json',
                'x-dfns-useraction': userAction,
            },
            method: 'POST',
        });

        if (!response.ok) {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: `Dfns signing API error: ${response.status}`,
                status: response.status,
            });
        }

        let sigResponse: GenerateSignatureResponse;
        try {
            sigResponse = (await response.json()) as GenerateSignatureResponse;
        } catch {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Failed to parse Dfns signature response',
            });
        }

        if (sigResponse.status === 'Failed') {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Dfns signing failed',
            });
        }

        if (sigResponse.status !== 'Signed') {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Unexpected signature status: ${sigResponse.status} (may require policy approval)`,
            });
        }

        if (!sigResponse.signature) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Signature components missing from response',
            });
        }

        return this.combineSignature(sigResponse.signature.r, sigResponse.signature.s);
    }

    /**
     * Combine r and s hex-encoded components into a 64-byte Ed25519 signature
     */
    private combineSignature(r: string, s: string): SignatureBytes {
        const rBytes = hexToBytes(r);
        const sBytes = hexToBytes(s);
        if (rBytes.length + sBytes.length !== 64) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Invalid signature length: expected 64 bytes, got ${rBytes.length + sBytes.length}`,
            });
        }
        const combined = new Uint8Array(64);
        combined.set(rBytes, 0);
        combined.set(sBytes, rBytes.length);
        return combined as SignatureBytes;
    }

    /**
     * Ensure the signer has been initialized
     */
    private ensureInitialized(): void {
        if (!this.initialized) {
            throwSignerError(SignerErrorCode.SIGNER_NOT_INITIALIZED, {
                message: 'Signer not initialized. Call init() first.',
            });
        }
    }
}
