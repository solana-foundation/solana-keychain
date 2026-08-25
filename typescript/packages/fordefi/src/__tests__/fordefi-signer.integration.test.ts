import { describe, expect, it } from 'vitest';
import { runSignerIntegrationTest } from '@solana/keychain-test-utils';
import {
    AccountRole,
    address,
    appendTransactionMessageInstruction,
    blockhash,
    compileTransaction,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { getCompiledTransactionMessageDecoder } from '@solana/transaction-messages';
import { COMPUTE_BUDGET_PROGRAM_ADDRESS } from '../compute-budget';
import { createManualSigner, getConfig, hasManualEnv } from './setup';
import { config } from 'dotenv';
config();

// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so we extend the per-test timeout well beyond the
// vitest default of 30s.
const TEST_TIMEOUT_MS = 120_000;

/**
 * Independent projection of what native manual mode may not change: everything
 * except the blockhash and the Compute Budget fee instructions Fordefi manages.
 * Kept deliberately separate from the production validator (which already ran
 * inside the signer, with the strict per-instruction checks) so a bug there
 * does not silently blind this assertion too.
 */
function comparableLiveManualMessage(messageBytes: ArrayLike<number>) {
    const message = getCompiledTransactionMessageDecoder().decode(new Uint8Array(Array.from(messageBytes)));
    if (message.version !== 0) {
        throw new Error('native manual integration fixture must compile to a v0 message');
    }
    return {
        addressTableLookups: message.addressTableLookups,
        instructions: message.instructions
            .filter(
                instruction =>
                    message.staticAccounts[instruction.programAddressIndex] !== COMPUTE_BUDGET_PROGRAM_ADDRESS,
            )
            .map(instruction => ({
                accountAddresses: (instruction.accountIndices ?? []).map(index => message.staticAccounts[index]),
                data: instruction.data ? Array.from(instruction.data) : undefined,
                programAddress: message.staticAccounts[instruction.programAddressIndex],
            })),
        nonComputeBudgetAccounts: message.staticAccounts.filter(account => account !== COMPUTE_BUDGET_PROGRAM_ADDRESS),
        signerAccounts: message.staticAccounts.slice(0, message.header.numSignerAccounts),
        version: message.version,
    };
}

describe('FordefiSigner Integration', () => {
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signTransaction']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'signs messages with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['signMessage']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!process.env.FORDEFI_BB_VAULT_ID)(
        'simulates transactions with real API',
        async () => {
            await runSignerIntegrationTest(await getConfig(['simulateTransaction']));
        },
        TEST_TIMEOUT_MS,
    );
    it.skipIf(!hasManualEnv())(
        'returns a native manual transaction without broadcasting it',
        async () => {
            const vaultAddress = address(process.env.FORDEFI_PUBLIC_KEY!);
            const transferData = new Uint8Array(12);
            const transferDataView = new DataView(transferData.buffer);
            transferDataView.setUint32(0, 2, true); // System Program: Transfer
            transferDataView.setBigUint64(4, 0n, true);

            const transaction = compileTransaction(
                pipe(
                    createTransactionMessage({ version: 0 }),
                    message => setTransactionMessageFeePayer(vaultAddress, message),
                    message =>
                        setTransactionMessageLifetimeUsingBlockhash(
                            {
                                blockhash: blockhash('11111111111111111111111111111111'),
                                lastValidBlockHeight: 0n,
                            },
                            message,
                        ),
                    message =>
                        appendTransactionMessageInstruction(
                            {
                                accounts: [
                                    { address: vaultAddress, role: AccountRole.WRITABLE_SIGNER },
                                    { address: vaultAddress, role: AccountRole.WRITABLE },
                                ],
                                data: transferData,
                                programAddress: address('11111111111111111111111111111111'),
                            },
                            message,
                        ),
                ),
            );
            const signer = await createManualSigner();

            const [signedTransaction] = await signer.modifyAndSignTransactions([transaction]);
            if (!signedTransaction?.signatures[vaultAddress]) {
                throw new Error('Fordefi manual response did not contain the vault signature');
            }
            expect(comparableLiveManualMessage(signedTransaction.messageBytes)).toEqual(
                comparableLiveManualMessage(transaction.messageBytes),
            );
            if ('signAndSendTransactions' in signer || 'signTransactions' in signer) {
                throw new Error('Fordefi manual signer exposed an incompatible transaction method');
            }
        },
        TEST_TIMEOUT_MS,
    );
});
