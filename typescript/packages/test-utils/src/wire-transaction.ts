import type { Address, Base64EncodedWireTransaction, ReadonlyUint8Array, SignatureBytes } from '@solana/kit';
import {
    appendTransactionMessageInstruction,
    compileTransaction,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
    partiallySignTransaction,
    pipe,
    setTransactionMessageComputeUnitLimit,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    setTransactionMessageLoadedAccountsDataSizeLimit,
} from '@solana/kit';

const SYSTEM_PROGRAM = '11111111111111111111111111111111' as Address;
const ZERO_BLOCKHASH = '11111111111111111111111111111111';

/**
 * A v1 message must carry explicit resource limits: unlike legacy and v0, an
 * unset compute unit limit or loaded accounts data size means zero, not a
 * default, and the transaction cannot execute.
 */
const V1_COMPUTE_UNIT_LIMIT = 30_000;
const V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 65_536;

export interface SignedWireTransaction {
    feePayer: Address;
    messageBytes: ReadonlyUint8Array;
    signature: SignatureBytes;
    wireTransaction: Base64EncodedWireTransaction;
}

/**
 * Build a real, fully signed wire transaction of the requested version.
 *
 * Version 1 puts `0x80 | 1` at offset zero and moves its signatures to the tail,
 * so a fixture built by hand from the legacy layout cannot stand in for one.
 */
export async function createSignedWireTransaction(version: 0 | 1): Promise<SignedWireTransaction> {
    const feePayerSigner = await generateKeyPairSigner();

    const message = pipe(
        createTransactionMessage({ version }),
        tx => setTransactionMessageFeePayer(feePayerSigner.address, tx),
        tx =>
            setTransactionMessageLifetimeUsingBlockhash(
                {
                    blockhash: ZERO_BLOCKHASH as Parameters<
                        typeof setTransactionMessageLifetimeUsingBlockhash
                    >[0]['blockhash'],
                    lastValidBlockHeight: 100n,
                },
                tx,
            ),
        tx => appendTransactionMessageInstruction({ programAddress: SYSTEM_PROGRAM }, tx),
        tx =>
            version === 1
                ? setTransactionMessageLoadedAccountsDataSizeLimit(
                      V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
                      setTransactionMessageComputeUnitLimit(V1_COMPUTE_UNIT_LIMIT, tx),
                  )
                : tx,
    );

    const signed = await partiallySignTransaction([feePayerSigner.keyPair], compileTransaction(message));
    const signature = signed.signatures[feePayerSigner.address];
    if (!signature) {
        throw new Error(`fixture transaction was not signed by its fee payer ${feePayerSigner.address}`);
    }

    return {
        feePayer: feePayerSigner.address,
        messageBytes: signed.messageBytes,
        signature,
        wireTransaction: getBase64EncodedWireTransaction(signed),
    };
}
