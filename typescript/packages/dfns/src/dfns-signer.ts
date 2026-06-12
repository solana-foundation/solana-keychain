import { Address, assertIsAddress } from '@solana/addresses';
import { getBase16Decoder, getBase16Encoder, getBase58Decoder } from '@solana/codecs-strings';
import {
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    fetchSignerJson,
    signBatchStaggered,
    SignerErrorCode,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import { SignableMessage, SignatureDictionary } from '@solana/signers';
import {
    getTransactionEncoder,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';

import type { DfnsCredentialKey } from './auth.js';
import { importDfnsCredentialKey, signUserAction } from './auth.js';
import type {
    DfnsSignerConfig,
    GenerateSignatureRequest,
    GenerateSignatureResponse,
    GetWalletResponse,
} from './types.js';

/**
 * Create and initialize a Dfns-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` when `privateKeyPem` cannot be imported.
 * @throws {SignerError} `SIGNER_HTTP_ERROR`, `SIGNER_REMOTE_API_ERROR`, `SIGNER_PARSING_ERROR`,
 * or `SIGNER_INVALID_PUBLIC_KEY` when initialization fails.
 */
export async function createDfnsSigner<TAddress extends string = string>(
    config: DfnsSignerConfig,
): Promise<SolanaSigner<TAddress>> {
    return await DfnsSigner.create(config);
}

const DEFAULT_API_BASE_URL = 'https://api.dfns.io';

let base16Encoder: ReturnType<typeof getBase16Encoder> | undefined;
let base16Decoder: ReturnType<typeof getBase16Decoder> | undefined;
let base58Decoder: ReturnType<typeof getBase58Decoder> | undefined;

function hexToBytes(hex: string): Uint8Array {
    base16Encoder ||= getBase16Encoder();
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length % 2 !== 0) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Invalid hex string from Dfns API: odd length (${clean.length} chars)`,
        });
    }
    return new Uint8Array(base16Encoder.encode(clean));
}

function bytesToHex(bytes: Uint8Array): string {
    base16Decoder ||= getBase16Decoder();
    return base16Decoder.decode(bytes);
}
function bytesToBase58(bytes: Uint8Array): string {
    base58Decoder ||= getBase58Decoder();
    return base58Decoder.decode(bytes);
}

/**
 * Dfns-based signer for Solana transactions.
 *
 * Uses Dfns Keys API to sign Solana transactions and messages.
 * Requires a Dfns account with an active Ed25519 Solana wallet.
 *
 * Use the static `create()` factory to construct an instance — it validates
 * the wallet status, key scheme, and curve via the Dfns API.
 *
 * @example
 * ```typescript
 * const signer = await DfnsSigner.create({
 *   authToken: 'your-service-account-token',
 *   credId: 'your-credential-id',
 *   privateKeyPem: '-----BEGIN PRIVATE KEY-----\n...',
 *   walletId: 'your-wallet-id',
 * });
 * const signed = await signTransactionMessageWithSigners(transactionMessage, [signer]);
 * ```
 *
 * @deprecated Prefer `createDfnsSigner()`. Class export will be removed in a future version.
 */
export class DfnsSigner<TAddress extends string = string> implements SolanaSigner<TAddress> {
    readonly address: Address<TAddress>;
    private readonly authToken: string;
    private readonly credId: string;
    private readonly credentialKey: DfnsCredentialKey;
    private readonly walletId: string;
    private readonly apiBaseUrl: string;
    private readonly keyId: string;

    private readonly requestDelayMs: number;

    private constructor(config: {
        address: Address<TAddress>;
        apiBaseUrl: string;
        authToken: string;
        credId: string;
        credentialKey: DfnsCredentialKey;
        keyId: string;
        requestDelayMs: number;
        walletId: string;
    }) {
        this.address = config.address;
        this.authToken = config.authToken;
        this.credId = config.credId;
        this.credentialKey = config.credentialKey;
        this.walletId = config.walletId;
        this.apiBaseUrl = config.apiBaseUrl;
        this.keyId = config.keyId;
        this.requestDelayMs = config.requestDelayMs;
    }

    /**
     * Create and initialize a DfnsSigner.
     *
     * Validates config fields, fetches the wallet from Dfns, and checks that
     * the wallet is active with an EdDSA/ed25519 signing key.
     * @deprecated Use `createDfnsSigner()` instead.
     */
    static async create<TAddress extends string = string>(config: DfnsSignerConfig): Promise<DfnsSigner<TAddress>> {
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

        const apiBaseUrl = config.apiBaseUrl ?? DEFAULT_API_BASE_URL;
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');
        const requestDelayMs = config.requestDelayMs ?? 0;
        validateRequestDelayMs(requestDelayMs);

        const credentialKey = await importDfnsCredentialKey(config.privateKeyPem);
        const wallet = await fetchWallet(apiBaseUrl, config.authToken, config.walletId);

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

        let address: Address<TAddress>;
        try {
            assertIsAddress(bs58Address);
            address = bs58Address as Address<TAddress>;
        } catch (error) {
            throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Invalid public key from Dfns wallet',
            });
        }

        return new DfnsSigner<TAddress>({
            address,
            apiBaseUrl,
            authToken: config.authToken,
            credId: config.credId,
            credentialKey,
            keyId: wallet.signingKey.id,
            requestDelayMs,
            walletId: config.walletId,
        });
    }

    /**
     * Sign multiple messages using Dfns
     */
    async signMessages(messages: readonly SignableMessage[]): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const messageBytes =
                    message.content instanceof Uint8Array
                        ? message.content
                        : new Uint8Array(Array.from(message.content));
                const signatureBytes = await this.sendSignatureRequest({
                    kind: 'Message',
                    message: `0x${bytesToHex(messageBytes)}`,
                });
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
     * Sign multiple transactions using Dfns
     */
    async signTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
    ): Promise<readonly SignatureDictionary[]> {
        const txEncoder = getTransactionEncoder();
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const txBytes = txEncoder.encode(transaction);
                const signatureBytes = await this.sendSignatureRequest({
                    blockchainKind: 'Solana',
                    kind: 'Transaction',
                    transaction: `0x${bytesToHex(new Uint8Array(txBytes))}`,
                });
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
        );
    }

    /**
     * Check if the Dfns wallet is available and healthy: reachable, active,
     * and backed by an EdDSA/ed25519 signing key.
     */
    async isAvailable(): Promise<boolean> {
        try {
            const wallet = await fetchWallet(this.apiBaseUrl, this.authToken, this.walletId);
            return (
                wallet.status === 'Active' &&
                wallet.signingKey.scheme === 'EdDSA' &&
                wallet.signingKey.curve === 'ed25519'
            );
        } catch {
            return false;
        }
    }

    /**
     * Send a signature request to the Dfns Keys API
     */
    private async sendSignatureRequest(request: GenerateSignatureRequest): Promise<SignatureBytes> {
        // keyId is server-issued (from the wallet response) and this path is signed into the
        // Dfns user-action challenge, which must match the routed request path verbatim — so it
        // is interpolated raw rather than percent-encoded.
        const httpPath = `/keys/${this.keyId}/signatures`;
        const requestBody = JSON.stringify(request);

        const userAction = await signUserAction(
            this.apiBaseUrl,
            this.authToken,
            this.credId,
            this.credentialKey,
            'POST',
            httpPath,
            requestBody,
        );

        const rawSigResponse = await fetchSignerJson<unknown>({
            init: {
                body: requestBody,
                headers: {
                    Authorization: `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json',
                    'x-dfns-useraction': userAction,
                },
                method: 'POST',
            },
            providerName: 'Dfns',
            url: `${this.apiBaseUrl}${httpPath}`,
        });

        const sigResponse = parseSignatureResponse(rawSigResponse);

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

        return combineSignature(sigResponse.signature.r, sigResponse.signature.s);
    }
}

/**
 * Fetch wallet details from Dfns
 */
async function fetchWallet(apiBaseUrl: string, authToken: string, walletId: string): Promise<GetWalletResponse> {
    const rawWalletResponse = await fetchSignerJson<unknown>({
        init: {
            headers: {
                Authorization: `Bearer ${authToken}`,
            },
            method: 'GET',
        },
        providerName: 'Dfns',
        url: `${apiBaseUrl}/wallets/${encodeURIComponent(walletId)}`,
    });

    return parseWalletResponse(rawWalletResponse);
}

function parseSignatureResponse(raw: unknown): GenerateSignatureResponse {
    if (!isObject(raw) || typeof raw.status !== 'string') {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns signature response shape',
        });
    }

    if (raw.signature !== undefined) {
        if (!isObject(raw.signature) || typeof raw.signature.r !== 'string' || typeof raw.signature.s !== 'string') {
            throwSignerError(SignerErrorCode.PARSING_ERROR, {
                message: 'Unexpected Dfns signature components shape',
            });
        }
    }

    return raw as unknown as GenerateSignatureResponse;
}

function parseWalletResponse(raw: unknown): GetWalletResponse {
    if (!isObject(raw) || typeof raw.status !== 'string' || !isObject(raw.signingKey)) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns wallet response shape',
        });
    }

    if (
        typeof raw.signingKey.id !== 'string' ||
        typeof raw.signingKey.scheme !== 'string' ||
        typeof raw.signingKey.curve !== 'string' ||
        typeof raw.signingKey.publicKey !== 'string'
    ) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns wallet signing key shape',
        });
    }

    return raw as unknown as GetWalletResponse;
}

function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

/**
 * Pad signature component to exactly 32 bytes.
 * Components from Dfns may be shorter than 32 bytes and need left-padding with zeros.
 */
function padSignatureComponent(hex: string): Uint8Array {
    const bytes = hexToBytes(hex);

    if (bytes.length > 32) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: `Invalid signature component length: ${bytes.length} (max 32)`,
        });
    }

    const padded = new Uint8Array(32);
    padded.set(bytes, 32 - bytes.length);
    return padded;
}

/**
 * Combine r and s hex-encoded components into a 64-byte Ed25519 signature.
 * Each component is individually validated and left-padded to 32 bytes.
 */
function combineSignature(r: string, s: string): SignatureBytes {
    const rBytes = padSignatureComponent(r);
    const sBytes = padSignatureComponent(s);
    const combined = new Uint8Array(64);
    combined.set(rBytes, 0);
    combined.set(sBytes, 32);
    return combined as SignatureBytes;
}
