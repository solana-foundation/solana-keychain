import { describe, expect, it } from 'vitest';
import { COMPUTE_BUDGET_PROGRAM_ADDRESS } from '@solana-program/compute-budget';
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
import { createFordefiSigner } from '../fordefi-signer';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so we extend the per-test timeout well beyond the
// vitest default of 30s.
const TEST_TIMEOUT_MS = 120_000;
function normalizeLiveManualMessage(messageBytes: ArrayLike<number>) {
    const message = getCompiledTransactionMessageDecoder().decode(new Uint8Array(Array.from(messageBytes)));
    if (message.version !== 0) {
        throw new Error('native manual integration fixture must compile to a v0 message');
    }

    let limitSeen = false;
    let priceSeen = false;
    const instructions = message.instructions.flatMap(instruction => {
        const programAddress = message.staticAccounts[instruction.programAddressIndex];
        const opcode = instruction.data?.[0];
        if (programAddress === COMPUTE_BUDGET_PROGRAM_ADDRESS && (opcode === 2 || opcode === 3)) {
            if ((instruction.accountIndices?.length ?? 0) !== 0) {
                throw new Error('live Fordefi fee instruction unexpectedly referenced accounts');
            }
            if (opcode === 2) {
                if (limitSeen || instruction.data?.length !== 5) {
                    throw new Error('live Fordefi compute-unit limit was malformed or duplicated');
                }
                const limit = Buffer.from(instruction.data).readUInt32LE(1);
                if (limit === 0 || limit > 1_400_000) {
                    throw new Error('live Fordefi compute-unit limit was out of range');
                }
                limitSeen = true;
            } else {
                if (priceSeen || instruction.data?.length !== 9) {
                    throw new Error('live Fordefi compute-unit price was malformed or duplicated');
                }
                priceSeen = true;
            }
            return [];
        }
        return [
            {
                accountAddresses: (instruction.accountIndices ?? []).map(index => message.staticAccounts[index]),
                data: instruction.data ? Array.from(instruction.data) : undefined,
                programAddress,
            },
        ];
    });

    const computeBudgetPositions = message.staticAccounts.flatMap((account, index) =>
        account === COMPUTE_BUDGET_PROGRAM_ADDRESS ? [index] : [],
    );
    const retainedReferencesComputeBudget = instructions.some(
        instruction =>
            instruction.programAddress === COMPUTE_BUDGET_PROGRAM_ADDRESS ||
            instruction.accountAddresses.some(account => account === COMPUTE_BUDGET_PROGRAM_ADDRESS),
    );
    const pruneComputeBudget = computeBudgetPositions.length === 1 && !retainedReferencesComputeBudget;
    if (pruneComputeBudget) {
        const index = computeBudgetPositions[0]!;
        const readonlyNonSignerStart = message.staticAccounts.length - message.header.numReadonlyNonSignerAccounts;
        if (index < message.header.numSignerAccounts || index < readonlyNonSignerStart) {
            throw new Error('live Fordefi fee-only Compute Budget key had unexpected permissions');
        }
    }

    return {
        addressTableLookups: message.addressTableLookups,
        header: {
            ...message.header,
            numReadonlyNonSignerAccounts: message.header.numReadonlyNonSignerAccounts - (pruneComputeBudget ? 1 : 0),
        },
        instructions,
        staticAccounts: pruneComputeBudget
            ? message.staticAccounts.filter(account => account !== COMPUTE_BUDGET_PROGRAM_ADDRESS)
            : message.staticAccounts,
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
    it.skipIf(
        !process.env.FORDEFI_ACCESS_TOKEN ||
            !process.env.FORDEFI_PRIVATE_KEY_PEM ||
            !process.env.FORDEFI_VAULT_ID ||
            !process.env.FORDEFI_PUBLIC_KEY,
    )(
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
            const signer = await createFordefiSigner({
                accessToken: process.env.FORDEFI_ACCESS_TOKEN!,
                apiBaseUrl: process.env.FORDEFI_API_BASE_URL,
                chain: process.env.FORDEFI_CHAIN === 'solana_mainnet' ? 'solana_mainnet' : 'solana_devnet',
                maxPollAttempts: 110,
                pollIntervalMs: 1000,
                privateKeyPem: process.env.FORDEFI_PRIVATE_KEY_PEM!,
                publicKey: process.env.FORDEFI_PUBLIC_KEY!,
                pushMode: 'manual',
                vaultId: process.env.FORDEFI_VAULT_ID!,
            });

            const [signedTransaction] = await signer.modifyAndSignTransactions([transaction]);
            if (!signedTransaction?.signatures[vaultAddress]) {
                throw new Error('Fordefi manual response did not contain the vault signature');
            }
            expect(normalizeLiveManualMessage(signedTransaction.messageBytes)).toEqual(
                normalizeLiveManualMessage(transaction.messageBytes),
            );
            if ('signAndSendTransactions' in signer || 'signTransactions' in signer) {
                throw new Error('Fordefi manual signer exposed an incompatible transaction method');
            }
        },
        TEST_TIMEOUT_MS,
    );
});
