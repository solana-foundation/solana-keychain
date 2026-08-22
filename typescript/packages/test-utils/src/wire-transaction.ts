import type { Address, Base64EncodedWireTransaction, ReadonlyUint8Array, SignatureBytes } from '@solana/kit';
import {
    AccountRole,
    appendTransactionMessageInstruction,
    blockhash,
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
import { SYSTEM_PROGRAM_ADDRESS } from '@solana-program/system';

const ZERO_BLOCKHASH = blockhash('11111111111111111111111111111111');

// v1 treats an unset limit as zero, not a default.
const V1_COMPUTE_UNIT_LIMIT = 30_000;
const V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 65_536;

export interface SignedWireTransaction {
    feePayer: Address;
    messageBytes: ReadonlyUint8Array;
    signature: SignatureBytes;
    wireTransaction: Base64EncodedWireTransaction;
}

function buildMessage(version: 0 | 1, feePayer: Address, cosigner?: Address) {
    return pipe(
        createTransactionMessage({ version }),
        tx => setTransactionMessageFeePayer(feePayer, tx),
        tx =>
            setTransactionMessageLifetimeUsingBlockhash({ blockhash: ZERO_BLOCKHASH, lastValidBlockHeight: 100n }, tx),
        tx =>
            appendTransactionMessageInstruction(
                {
                    programAddress: SYSTEM_PROGRAM_ADDRESS,
                    ...(cosigner ? { accounts: [{ address: cosigner, role: AccountRole.READONLY_SIGNER }] } : {}),
                },
                tx,
            ),
        tx =>
            version === 1
                ? setTransactionMessageLoadedAccountsDataSizeLimit(
                      V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
                      setTransactionMessageComputeUnitLimit(V1_COMPUTE_UNIT_LIMIT, tx),
                  )
                : tx,
    );
}

/** A fully signed wire transaction of the requested version. */
export async function createSignedWireTransaction(version: 0 | 1): Promise<SignedWireTransaction> {
    const feePayerSigner = await generateKeyPairSigner();
    const message = buildMessage(version, feePayerSigner.address);

    const signed = await partiallySignTransaction([feePayerSigner.keyPair], compileTransaction(message));
    const signature = signed.signatures[feePayerSigner.address];
    if (!signature) {
        throw new Error(`fixture was not signed by its fee payer ${feePayerSigner.address}`);
    }

    return {
        feePayer: feePayerSigner.address,
        messageBytes: signed.messageBytes,
        signature,
        wireTransaction: getBase64EncodedWireTransaction(signed),
    };
}

export interface CosignedWireTransaction {
    cosigner: Address;
    feePayer: Address;
    wireTransaction: Base64EncodedWireTransaction;
}

/** A wire transaction whose cosigner signed but whose fee-payer slot is empty. */
export async function createCosignedWireTransaction(version: 0 | 1): Promise<CosignedWireTransaction> {
    const feePayerSigner = await generateKeyPairSigner();
    const cosigner = await generateKeyPairSigner();
    const message = buildMessage(version, feePayerSigner.address, cosigner.address);

    const signed = await partiallySignTransaction([cosigner.keyPair], compileTransaction(message));
    if (!signed.signatures[cosigner.address]) {
        throw new Error(`fixture was not signed by its cosigner ${cosigner.address}`);
    }
    if (signed.signatures[feePayerSigner.address]) {
        throw new Error('fixture should leave the fee-payer slot unsigned');
    }

    return {
        cosigner: cosigner.address,
        feePayer: feePayerSigner.address,
        wireTransaction: getBase64EncodedWireTransaction(signed),
    };
}
