import { Address, assertIsAddress, getAddressEncoder } from '@solana/addresses';
import { ReadonlyUint8Array } from '@solana/codecs-core';
import { getBase64Encoder } from '@solana/codecs-strings';
import { SignatureBytes, verifySignature } from '@solana/keys';
import { isMessagePartialSigner, isTransactionPartialSigner, SignatureDictionary } from '@solana/signers';
import { Base64EncodedWireTransaction, getTransactionDecoder } from '@solana/transactions';

import { SignerErrorCode, throwSignerError } from './errors.js';
import { SolanaSigner } from './types.js';

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
    assertIsAddress(signerAddress);
    const encoder = getBase64Encoder();
    const decoder = getTransactionDecoder();
    const transactionBytes = encoder.encode(base64WireTransaction);
    const { signatures } = decoder.decode(transactionBytes);

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
