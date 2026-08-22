import { describe, it } from 'vitest';
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
import { createFordefiSigner } from '../fordefi-signer';
import { getConfig } from './setup';
import { config } from 'dotenv';
config();

// Fordefi MPC signing can take tens of seconds end-to-end (submit + poll until
// the co-signers finish), so we extend the per-test timeout well beyond the
// vitest default of 30s.
const TEST_TIMEOUT_MS = 120_000;

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
            if ('signAndSendTransactions' in signer || 'signTransactions' in signer) {
                throw new Error('Fordefi manual signer exposed an incompatible transaction method');
            }
        },
        TEST_TIMEOUT_MS,
    );
});
