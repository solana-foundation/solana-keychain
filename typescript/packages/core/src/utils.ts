import { Address, assertIsAddress, getAddressEncoder } from '@solana/addresses';
import { ReadonlyUint8Array } from '@solana/codecs-core';
import { getBase64Encoder } from '@solana/codecs-strings';
import { SignatureBytes, verifySignature } from '@solana/keys';
import {
    isMessagePartialSigner,
    isTransactionModifyingSigner,
    isTransactionPartialSigner,
    isTransactionSendingSigner,
    SignatureDictionary,
} from '@solana/signers';
import { Base64EncodedWireTransaction, getTransactionDecoder } from '@solana/transactions';

import { SignerErrorCode, throwSignerError } from './errors.js';
import { SolanaModifyingSigner, SolanaSendingSigner, SolanaSigner } from './types.js';

/**
 * A UUID derived from SHA-256(message bytes), so a retry of the same bytes
 * reuses the key and the provider deduplicates the create.
 */
export async function idempotencyKeyFromMessage(messageBytes: ReadonlyUint8Array): Promise<string> {
    const { createHash } = await import('node:crypto');
    const digest = createHash('sha256').update(new Uint8Array(messageBytes)).digest().subarray(0, 16);
    digest[6] = (digest[6]! & 0x0f) | 0x40;
    digest[8] = (digest[8]! & 0x3f) | 0x80;
    const hex = digest.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

interface AssertSignatureValidOptions {
    data: ReadonlyUint8Array;
    signature: SignatureBytes;
    signerAddress: Address;
}

/**
 * Verifies that an Ed25519 signature is valid for the given data and signer address.
 * Throws a SIGNING_FAILED error if the signature does not match.
 *
 * @param signerAddress - The address (public key) of the signer
 * @param signature - The 64-byte Ed25519 signature to verify
 * @param data - The original data that was signed
 * @throws {SignerError} If the signature verification fails
 */
export async function assertSignatureValid({
    data,
    signature,
    signerAddress,
}: AssertSignatureValidOptions): Promise<void> {
    const addressBytes = getAddressEncoder().encode(signerAddress);

    let publicKey: CryptoKey;
    try {
        publicKey = await crypto.subtle.importKey('raw', addressBytes, { name: 'Ed25519' }, false, ['verify']);
    } catch (error) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signerAddress,
            cause: error,
            message: `Failed to import public key for signature verification: ${error instanceof Error ? error.message : String(error)}`,
        });
    }

    let valid: boolean;
    try {
        valid = await verifySignature(publicKey, signature, data);
    } catch (error) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signerAddress,
            cause: error,
            message: `Signature verification threw unexpectedly: ${error instanceof Error ? error.message : String(error)}`,
        });
    }

    if (!valid) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signerAddress,
            message: 'Signature verification failed: returned signature does not match public key and signed data',
        });
    }
}

interface ExtractSignatureFromTransactionBytesOptions {
    signerAddress: Address;
    transactionBytes: ReadonlyUint8Array;
}

/**
 * Extracts a specific signer's signature from decoded wire-transaction bytes.
 * Useful for remote signers that return the signed transaction as raw bytes,
 * avoiding a base64 encode/decode round-trip.
 *
 * @param transactionBytes - The serialized wire transaction
 * @param signerAddress - The address of the signer whose signature to extract
 * @returns SignatureDictionary with only the specified signer's signature
 * @throws {SignerError} If no signature is found for the given address
 */
export function extractSignatureFromTransactionBytes({
    signerAddress,
    transactionBytes,
}: ExtractSignatureFromTransactionBytesOptions): SignatureDictionary {
    assertIsAddress(signerAddress);
    const { signatures } = getTransactionDecoder().decode(transactionBytes);

    const signature = signatures[signerAddress];
    if (!signature) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signerAddress,
            message: `No signature found for address ${signerAddress}`,
        });
    }

    return createSignatureDictionary({
        signature,
        signerAddress,
    });
}

interface ExtractSignatureFromWireTransactionOptions {
    base64WireTransaction: Base64EncodedWireTransaction;
    signerAddress: Address;
}

/**
 * Extracts a specific signer's signature from a base64-encoded wire transaction.
 * Useful for remote signers that return fully signed transactions from their APIs.
 *
 * @param base64WireTransaction - Base64 encoded transaction string
 * @param signerAddress - The address of the signer whose signature to extract
 * @returns SignatureDictionary with only the specified signer's signature
 * @throws {SignerError} If no signature is found for the given address
 *
 * @example
 * ```typescript
 * // Privy API returns a signed transaction
 * const signedTx = await privyApi.signTransaction(...);
 * const sigDict = extractSignatureFromWireTransaction(signedTx, this.address);
 * ```
 */
export function extractSignatureFromWireTransaction({
    base64WireTransaction,
    signerAddress,
}: ExtractSignatureFromWireTransactionOptions): SignatureDictionary {
    return extractSignatureFromTransactionBytes({
        signerAddress,
        transactionBytes: getBase64Encoder().encode(base64WireTransaction),
    });
}

interface CreateSignatureDictionaryArgs {
    signature: SignatureBytes;
    signerAddress: Address;
}

/**
 * Creates a signature dictionary from a signature and signer address.
 * @param signature - The signature to create the dictionary from
 * @param signerAddress - The address of the signer whose signature to create the dictionary from
 * @returns SignatureDictionary with only the specified signer's signature
 * @throws {SignerError} If no signature is found for the given address
 *
 * @example
 * ```typescript
 * const sigDict = createSignatureDictionary({ signature, signerAddress });
 * ```
 */
export function createSignatureDictionary({
    signature,
    signerAddress,
}: CreateSignatureDictionaryArgs): SignatureDictionary {
    assertIsAddress(signerAddress);
    if (!signature) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signerAddress,
            message: `No signature found for address ${signerAddress}`,
        });
    }
    return Object.freeze({ [signerAddress]: signature });
}

/**
 * Checks if the given value is a SolanaSigner.
 * @param value - The value to check
 * @returns True if the value is a SolanaSigner, false otherwise
 */
export function isSolanaSigner<TAddress extends string>(value: {
    address: Address<TAddress>;
}): value is SolanaSigner<TAddress> {
    return (
        'address' in value &&
        'isAvailable' in value &&
        isMessagePartialSigner(value) &&
        isTransactionPartialSigner(value)
    );
}

/**
 * Checks if the given value is a SolanaSendingSigner (a managed-broadcast
 * signer). Such signers expose `signAndSendTransactions` and, by design, no
 * `signTransactions`, so they are never also a {@link SolanaSigner}.
 * @param value - The value to check
 * @returns True if the value is a SolanaSendingSigner, false otherwise
 */
export function isSolanaSendingSigner<TAddress extends string>(value: {
    address: Address<TAddress>;
}): value is SolanaSendingSigner<TAddress> {
    return 'address' in value && 'isAvailable' in value && isTransactionSendingSigner(value);
}

/**
 * Checks if the given value is a SolanaModifyingSigner. Such signers expose
 * `modifyAndSignTransactions` and, by design, no `signTransactions`, so they are
 * never also a {@link SolanaSigner}.
 * @param value - The value to check
 * @returns True if the value is a SolanaModifyingSigner, false otherwise
 */
export function isSolanaModifyingSigner<TAddress extends string>(value: {
    address: Address<TAddress>;
}): value is SolanaModifyingSigner<TAddress> {
    return 'address' in value && 'isAvailable' in value && isTransactionModifyingSigner(value);
}

/**
 * The signing methods a signer actually exposes. Kit classifies signers by
 * method presence, so this reports what a signer can be used for rather than
 * which interface it nominally implements.
 */
export type SignerCapabilities = Readonly<{
    /** The signer rewrites the transaction and returns the signed result. */
    canModifyAndSignTransactions: boolean;
    /** The signer signs and broadcasts through its provider. */
    canSignAndSend: boolean;
    /** The signer signs off-chain messages. */
    canSignMessages: boolean;
    /** The signer returns signatures for a caller-owned transaction. */
    canSignTransactions: boolean;
}>;

/**
 * Reports which signing methods the given signer exposes.
 * @param signer - The signer to inspect
 */
export function signerCapabilities(signer: { address: Address }): SignerCapabilities {
    return Object.freeze({
        canModifyAndSignTransactions: isTransactionModifyingSigner(signer),
        canSignAndSend: isTransactionSendingSigner(signer),
        canSignMessages: isMessagePartialSigner(signer),
        canSignTransactions: isTransactionPartialSigner(signer),
    });
}

/**
 * Asserts that the given value is a SolanaSigner, throwing an error if it is not.
 * @param value - The value to check
 * @throws {SignerError} If the value is not a SolanaSigner
 */
export function assertIsSolanaSigner<TAddress extends string>(value: {
    address: Address<TAddress>;
}): asserts value is SolanaSigner<TAddress> {
    if (!isSolanaSigner(value)) {
        throwSignerError(SignerErrorCode.EXPECTED_SOLANA_SIGNER, {
            address: value.address,
        });
    }
}

export function normalizePrivateKeyPem(privateKeyPem: string): string {
    return privateKeyPem.replace(/\\n/g, '\n').replace(/\r/g, '').trim();
}
