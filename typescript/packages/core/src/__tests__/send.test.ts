import type { Address } from '@solana/addresses';
import type { SignatureBytes } from '@solana/keys';
import type { SignatureDictionary } from '@solana/signers';
import type { Transaction, TransactionWithinSizeLimit, TransactionWithLifetime } from '@solana/transactions';
import { describe, expect, it, vi } from 'vitest';

import { SignerErrorCode } from '../errors.js';
import { type SendTransactionFn, signAndSendTransaction } from '../send.js';

type SignableTransaction = Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;

const FEE_PAYER = 'FeePayer111111111111111111111111111111111111' as Address;
const SIGNER_ADDRESS = 'Signer1111111111111111111111111111111111111' as Address;

function signatureBytes(seed: number): SignatureBytes {
    return new Uint8Array(64).fill(seed) as unknown as SignatureBytes;
}

const FEE_PAYER_SIGNATURE = signatureBytes(1);
const SIGNER_SIGNATURE = signatureBytes(2);
const SENT_SIGNATURE = signatureBytes(3);
const REWRITTEN_FEE_PAYER_SIGNATURE = signatureBytes(4);

function createTransaction(): SignableTransaction {
    return {
        '"__transactionSize:@solana/kit"': 100,
        lifetimeConstraint: { blockhash: 'Blockhash11111111111111111111111111111111111', lastValidBlockHeight: 100n },
        messageBytes: new Uint8Array([1, 2, 3, 4]),
        signatures: { [FEE_PAYER]: FEE_PAYER_SIGNATURE, [SIGNER_ADDRESS]: null },
    } as unknown as SignableTransaction;
}

function createPartialSigner(overrides?: { signatures?: SignatureDictionary }) {
    return {
        address: SIGNER_ADDRESS,
        isAvailable: async () => true,
        signMessages: vi.fn(async () => []),
        signTransactions: vi.fn(async () => [
            overrides?.signatures ?? ({ [SIGNER_ADDRESS]: SIGNER_SIGNATURE } as SignatureDictionary),
        ]),
    };
}

function createSendingSigner() {
    return {
        address: SIGNER_ADDRESS,
        isAvailable: async () => true,
        signAndSendTransactions: vi.fn(async () => [SENT_SIGNATURE]),
    };
}

function createModifyingSigner(overrides?: { transactions?: SignableTransaction[] }) {
    return {
        address: SIGNER_ADDRESS,
        isAvailable: async () => true,
        modifyAndSignTransactions: vi.fn(async (transactions: readonly SignableTransaction[]) => {
            if (overrides?.transactions) {
                return overrides.transactions;
            }
            const [transaction] = transactions;
            return [
                Object.freeze({
                    ...transaction!,
                    signatures: Object.freeze({ ...transaction!.signatures, [SIGNER_ADDRESS]: SIGNER_SIGNATURE }),
                }) as SignableTransaction,
            ];
        }),
    };
}

describe('signAndSendTransaction', () => {
    it('broadcasts through a sending signer', async () => {
        const signer = createSendingSigner();
        const transaction = createTransaction();
        const sendTransaction = vi.fn<SendTransactionFn>(async () => undefined);

        const signature = await signAndSendTransaction(signer, transaction, { sendTransaction });

        expect(signature).toBe(SENT_SIGNATURE);
        expect(signer.signAndSendTransactions).toHaveBeenCalledWith([transaction], { abortSignal: undefined });
        expect(sendTransaction).not.toHaveBeenCalled();
    });

    it('throws when a sending signer returns no signature', async () => {
        const signer = { ...createSendingSigner(), signAndSendTransactions: async () => [] };

        await expect(signAndSendTransaction(signer, createTransaction())).rejects.toMatchObject({
            code: SignerErrorCode.SIGNING_FAILED,
        });
    });

    it('signs then broadcasts through the injected send function', async () => {
        const signer = createPartialSigner();
        const transaction = createTransaction();
        const sendTransaction = vi.fn<SendTransactionFn>(async () => SENT_SIGNATURE);

        const signature = await signAndSendTransaction(signer, transaction, { sendTransaction });

        expect(signature).toBe(SENT_SIGNATURE);
        expect(signer.signTransactions).toHaveBeenCalledWith([transaction], { abortSignal: undefined });
        const [sentTransaction] = sendTransaction.mock.calls[0]!;
        expect(sentTransaction.signatures).toStrictEqual({
            [FEE_PAYER]: FEE_PAYER_SIGNATURE,
            [SIGNER_ADDRESS]: SIGNER_SIGNATURE,
        });
        expect(sentTransaction.messageBytes).toBe(transaction.messageBytes);
        expect(transaction.signatures[SIGNER_ADDRESS]).toBeNull();
    });

    it('falls back to the fee payer signature when the send function returns nothing', async () => {
        const sendTransaction = vi.fn<SendTransactionFn>(async () => undefined);

        const signature = await signAndSendTransaction(createPartialSigner(), createTransaction(), {
            sendTransaction,
        });

        expect(signature).toBe(FEE_PAYER_SIGNATURE);
    });

    it('broadcasts the transaction a modifying signer returns', async () => {
        const signer = createModifyingSigner();
        const transaction = createTransaction();
        const sendTransaction = vi.fn<SendTransactionFn>(async () => SENT_SIGNATURE);

        const signature = await signAndSendTransaction(signer, transaction, { sendTransaction });

        expect(signature).toBe(SENT_SIGNATURE);
        expect(signer.modifyAndSignTransactions).toHaveBeenCalledWith([transaction], { abortSignal: undefined });
        const [sentTransaction] = sendTransaction.mock.calls[0]!;
        expect(sentTransaction.signatures).toStrictEqual({
            [FEE_PAYER]: FEE_PAYER_SIGNATURE,
            [SIGNER_ADDRESS]: SIGNER_SIGNATURE,
        });
    });

    it('keeps the rewritten transaction signature when the send function rejects', async () => {
        const transaction = createTransaction();
        const rewritten = Object.freeze({
            ...transaction,
            signatures: Object.freeze({
                [FEE_PAYER]: REWRITTEN_FEE_PAYER_SIGNATURE,
                [SIGNER_ADDRESS]: SIGNER_SIGNATURE,
            }),
        }) as SignableTransaction;
        const callbackError = new Error('connection reset');

        await expect(
            signAndSendTransaction(createModifyingSigner({ transactions: [rewritten] }), transaction, {
                sendTransaction: async () => {
                    throw callbackError;
                },
            }),
        ).rejects.toMatchObject({
            cause: callbackError,
            code: SignerErrorCode.BROADCAST_UNCONFIRMED,
            context: { transactionSignature: REWRITTEN_FEE_PAYER_SIGNATURE },
        });
    });

    it('throws when a modifying signer returns no transaction', async () => {
        const signer = createModifyingSigner({ transactions: [] });

        await expect(
            signAndSendTransaction(signer, createTransaction(), { sendTransaction: async () => undefined }),
        ).rejects.toMatchObject({ code: SignerErrorCode.SIGNING_FAILED });
    });

    it('throws when a modifying signer returns a transaction with missing signatures', async () => {
        const signer = createModifyingSigner({ transactions: [createTransaction()] });

        await expect(
            signAndSendTransaction(signer, createTransaction(), { sendTransaction: async () => undefined }),
        ).rejects.toMatchObject({ code: SignerErrorCode.SIGNING_FAILED });
    });

    it('throws a config error when a modifying signer has no send function', async () => {
        const signer = createModifyingSigner();

        await expect(signAndSendTransaction(signer, createTransaction())).rejects.toMatchObject({
            code: SignerErrorCode.CONFIG_ERROR,
        });
        expect(signer.modifyAndSignTransactions).not.toHaveBeenCalled();
    });

    it('throws a config error when the signer cannot broadcast and no send function is given', async () => {
        const signer = createPartialSigner();

        await expect(signAndSendTransaction(signer, createTransaction())).rejects.toMatchObject({
            code: SignerErrorCode.CONFIG_ERROR,
        });
        expect(signer.signTransactions).not.toHaveBeenCalled();
    });

    it('throws when signatures are still missing after signing', async () => {
        const signer = createPartialSigner({ signatures: {} as SignatureDictionary });

        await expect(
            signAndSendTransaction(signer, createTransaction(), { sendTransaction: async () => undefined }),
        ).rejects.toMatchObject({ code: SignerErrorCode.SIGNING_FAILED });
    });

    it('propagates the abort signal to both paths', async () => {
        const abortSignal = new AbortController().signal;

        const sendingSigner = createSendingSigner();
        await signAndSendTransaction(sendingSigner, createTransaction(), { abortSignal });
        expect(sendingSigner.signAndSendTransactions).toHaveBeenCalledWith(expect.anything(), { abortSignal });

        const partialSigner = createPartialSigner();
        const sendTransaction = vi.fn<SendTransactionFn>(async () => SENT_SIGNATURE);
        await signAndSendTransaction(partialSigner, createTransaction(), { abortSignal, sendTransaction });
        expect(partialSigner.signTransactions).toHaveBeenCalledWith(expect.anything(), { abortSignal });
        expect(sendTransaction).toHaveBeenCalledWith(expect.anything(), { abortSignal });
    });
});
