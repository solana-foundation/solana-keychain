import type { Address } from '@solana/addresses';
import type { SignatureBytes } from '@solana/keys';
import type {
    SendableTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';
import { isFullySignedTransaction } from '@solana/transactions';

import { SignerErrorCode, throwSignerError } from './errors.js';
import type { SolanaModifyingSigner, SolanaSendingSigner, SolanaSigner } from './types.js';
import { isSolanaModifyingSigner, isSolanaSendingSigner } from './utils.js';

type SignableTransaction = Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;

/**
 * Broadcast function supplied by the caller, used when the signer cannot
 * broadcast on its own.
 *
 * Core has no RPC dependency, so the network hop is always injected. Implement
 * it with whatever transport the caller already has — a Kit
 * `sendAndConfirmTransaction` factory, a raw `rpc.sendTransaction` call, or a
 * relayer HTTP endpoint.
 *
 * @param transaction - The fully signed transaction to broadcast.
 * @returns The signature identifying the broadcast transaction, or nothing.
 * When nothing is returned, the fee payer's signature on the transaction is
 * used instead, so Kit's `void`-returning senders can be passed directly.
 */
export type SendTransactionFn = (
    transaction: SendableTransaction & SignableTransaction,
    config?: { abortSignal?: AbortSignal },
) => Promise<SignatureBytes | void>;

/**
 * Configuration for {@link signAndSendTransaction}.
 */
export type SignAndSendTransactionConfig = Readonly<{
    /** Aborts the signing request and the broadcast that follows it. */
    abortSignal?: AbortSignal;
    /**
     * Broadcast function, required for signers that only sign. Ignored by
     * managed-broadcast signers, which broadcast through their own provider.
     */
    sendTransaction?: SendTransactionFn;
}>;

/**
 * Gets a transaction on chain with one flow, whichever shape the signer has.
 *
 * A {@link SolanaSendingSigner} signs and broadcasts through its provider. A
 * {@link SolanaModifyingSigner} rewrites the transaction, signs it, and
 * `config.sendTransaction` broadcasts the transaction it returned — not the one
 * passed in, which no longer matches the signature. A {@link SolanaSigner} signs,
 * its signature is merged into the transaction, and `config.sendTransaction`
 * broadcasts the result.
 *
 * @param signer - Any keychain signer.
 * @param transaction - The transaction to sign and broadcast.
 * @returns The signature identifying the transaction that was broadcast.
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when the signer cannot broadcast
 * and no `sendTransaction` was supplied; `SIGNER_SIGNING_FAILED` when the signer
 * returns no signature or the transaction is still missing signatures after
 * signing. Backend-specific signing errors propagate unchanged.
 *
 * @example
 * ```typescript
 * const signature = await signAndSendTransaction(signer, transaction, {
 *     sendTransaction: tx => sendAndConfirmTransaction(tx, { commitment: 'confirmed' }),
 * });
 * ```
 */
export async function signAndSendTransaction<TAddress extends string>(
    signer: SolanaModifyingSigner<TAddress> | SolanaSendingSigner<TAddress> | SolanaSigner<TAddress>,
    transaction: SignableTransaction,
    config?: SignAndSendTransactionConfig,
): Promise<SignatureBytes> {
    const abortSignal = config?.abortSignal;

    if (isSolanaSendingSigner(signer)) {
        const [signature] = await signer.signAndSendTransactions([transaction], { abortSignal });
        if (!signature) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: signer.address,
                message: 'Signer returned no signature for the transaction it broadcast',
            });
        }
        return signature;
    }

    const sendTransaction = config?.sendTransaction;
    if (!sendTransaction) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            address: signer.address,
            message: 'This signer cannot broadcast transactions; supply `sendTransaction` to broadcast the signed one',
        });
    }

    if (isSolanaModifyingSigner(signer)) {
        // The signer rewrote the message, so only what it returned matches the
        // signature; the caller's original transaction is now stale.
        const [modifiedTransaction] = await signer.modifyAndSignTransactions([transaction], { abortSignal });
        if (!modifiedTransaction) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: signer.address,
                message: 'Signer returned no transaction',
            });
        }
        return await broadcast(signer.address, modifiedTransaction, sendTransaction, abortSignal);
    }

    const [signatureDictionary] = await signer.signTransactions([transaction], { abortSignal });
    if (!signatureDictionary) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address: signer.address,
            message: 'Signer returned no signatures for the transaction',
        });
    }

    const signedTransaction = Object.freeze({
        ...transaction,
        signatures: Object.freeze({ ...transaction.signatures, ...signatureDictionary }),
    });

    return await broadcast(signer.address, signedTransaction, sendTransaction, abortSignal);
}

/**
 * Rejects a transaction that is still missing signatures, broadcasts the rest,
 * and identifies it by the fee payer's signature when the sender returns none.
 */
async function broadcast(
    address: Address,
    transaction: SignableTransaction,
    sendTransaction: SendTransactionFn,
    abortSignal: AbortSignal | undefined,
): Promise<SignatureBytes> {
    if (!isFullySignedTransaction(transaction)) {
        const missing = Object.entries(transaction.signatures)
            .filter(([, signature]) => !signature)
            .map(([signerAddress]) => signerAddress);
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address,
            message: `Transaction is missing signatures for ${missing.join(', ')}`,
        });
    }

    const signature = await sendTransaction(transaction, { abortSignal });
    if (signature) {
        return signature;
    }

    const feePayerSignature = Object.values(transaction.signatures)[0];
    if (!feePayerSignature) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            address,
            message: 'Broadcast transaction has no fee payer signature to identify it by',
        });
    }
    return feePayerSignature;
}
