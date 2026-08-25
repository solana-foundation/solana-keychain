import { Address } from '@solana/addresses';
import { bytesEqual, type ReadonlyUint8Array } from '@solana/codecs-core';
import {
    type CompiledTransactionMessage,
    type CompiledTransactionMessageWithLifetime,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
} from '@solana/transaction-messages';
import { getTransactionLifetimeConstraintFromCompiledTransactionMessage } from '@solana/transactions';

import {
    COMPUTE_BUDGET_PROGRAM_ADDRESS,
    decodeSetComputeUnitLimitUnits,
    decodeSetComputeUnitPriceMicroLamports,
    MAX_COMPUTE_UNIT_LIMIT,
    SET_COMPUTE_UNIT_LIMIT_DATA_LENGTH,
    SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR,
    SET_COMPUTE_UNIT_PRICE_DATA_LENGTH,
    SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR,
} from './compute-budget.js';
import type { FordefiSolanaFee } from './types.js';

const MICRO_LAMPORTS_PER_LAMPORT = 1_000_000n;

/**
 * Default ceiling, in lamports, on a priority fee Fordefi introduces itself
 * during native manual signing, so a compromised or malfunctioning response
 * cannot drain the fee payer. Override via
 * {@link FordefiSignerConfig.maxPriorityFeeLamports}.
 */
export const DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 100_000_000n;

type DecodedCompiledMessage = CompiledTransactionMessage & CompiledTransactionMessageWithLifetime;
type LegacyOrV0CompiledMessage = Extract<DecodedCompiledMessage, { version: 'legacy' | 0 }>;
type MutableCompiledInstruction = {
    accountIndices?: number[];
    data?: Uint8Array;
    programAddressIndex: number;
};
/** Compute Budget values recovered from a message, in the units the instructions encode. */
type ManualFeeInstructions = { limit?: number; price?: bigint };
/** The caller's fee configuration, against which a returned fee is judged. */
export type ManualFeePolicy = { fee?: FordefiSolanaFee; maxPriorityFeeLamports?: bigint };

function encodeCompiledMessage(message: DecodedCompiledMessage): ReadonlyUint8Array {
    return getCompiledTransactionMessageEncoder().encode(message);
}

function compareManualMessagesExactly(
    original: DecodedCompiledMessage,
    returned: DecodedCompiledMessage,
    allowBlockhashReplacement: boolean,
): boolean {
    const comparable = allowBlockhashReplacement
        ? ({ ...returned, lifetimeToken: original.lifetimeToken } as DecodedCompiledMessage)
        : returned;
    return bytesEqual(encodeCompiledMessage(original), encodeCompiledMessage(comparable));
}

function normalizeManualFeeMessage(message: LegacyOrV0CompiledMessage): {
    fees: ManualFeeInstructions;
    message: LegacyOrV0CompiledMessage;
} {
    const normalized = {
        ...message,
        header: { ...message.header },
        instructions: message.instructions.map(instruction => ({
            ...instruction,
            accountIndices: instruction.accountIndices ? [...instruction.accountIndices] : undefined,
            data: instruction.data ? new Uint8Array(instruction.data) : undefined,
        })),
        staticAccounts: [...message.staticAccounts],
    } as LegacyOrV0CompiledMessage & {
        header: {
            numReadonlyNonSignerAccounts: number;
            numReadonlySignerAccounts: number;
            numSignerAccounts: number;
        };
        instructions: MutableCompiledInstruction[];
        staticAccounts: Address[];
    };
    const fees: ManualFeeInstructions = {};
    const retained: MutableCompiledInstruction[] = [];

    for (const instruction of normalized.instructions) {
        const programAddress = normalized.staticAccounts[instruction.programAddressIndex];
        const opcode = instruction.data?.[0];
        if (
            programAddress !== COMPUTE_BUDGET_PROGRAM_ADDRESS ||
            (opcode !== SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR && opcode !== SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR)
        ) {
            retained.push(instruction);
            continue;
        }
        if ((instruction.accountIndices?.length ?? 0) !== 0) {
            throw new Error('Fordefi returned an account-bearing Compute Budget fee instruction');
        }
        // The decoders read a fixed prefix, so they tolerate trailing bytes and
        // reject only a short buffer. An exact length check is what refuses a
        // padded instruction the runtime would still accept.
        if (opcode === SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR) {
            if (instruction.data?.length !== SET_COMPUTE_UNIT_LIMIT_DATA_LENGTH || fees.limit !== undefined) {
                throw new Error('Fordefi returned a malformed or duplicate compute-unit limit');
            }
            const units = decodeSetComputeUnitLimitUnits(instruction.data);
            if (units === 0 || units > MAX_COMPUTE_UNIT_LIMIT) {
                throw new Error('Fordefi returned an out-of-range compute-unit limit');
            }
            fees.limit = units;
        } else {
            if (instruction.data?.length !== SET_COMPUTE_UNIT_PRICE_DATA_LENGTH || fees.price !== undefined) {
                throw new Error('Fordefi returned a malformed or duplicate compute-unit price');
            }
            fees.price = decodeSetComputeUnitPriceMicroLamports(instruction.data);
        }
    }
    normalized.instructions = retained;

    const computeBudgetPositions = normalized.staticAccounts.flatMap((address, index) =>
        address === COMPUTE_BUDGET_PROGRAM_ADDRESS ? [index] : [],
    );
    if (computeBudgetPositions.length === 1) {
        const index = computeBudgetPositions[0]!;
        const readonlyNonSignerStart =
            normalized.staticAccounts.length - normalized.header.numReadonlyNonSignerAccounts;
        const referenced = normalized.instructions.some(
            instruction =>
                instruction.programAddressIndex === index || instruction.accountIndices?.includes(index) === true,
        );
        // Both bounds are checked: the header comes from Fordefi's returned
        // bytes and its counts are not validated to be mutually consistent, so
        // neither bound implies the other here.
        if (index >= normalized.header.numSignerAccounts && index >= readonlyNonSignerStart && !referenced) {
            normalized.staticAccounts.splice(index, 1);
            normalized.header.numReadonlyNonSignerAccounts--;
            for (const instruction of normalized.instructions) {
                if (instruction.programAddressIndex > index) {
                    instruction.programAddressIndex--;
                }
                instruction.accountIndices = instruction.accountIndices?.map(accountIndex =>
                    accountIndex > index ? accountIndex - 1 : accountIndex,
                );
            }
        }
    }
    return { fees, message: normalized };
}

/**
 * Total priority fee in lamports: micro-lamports per compute unit multiplied by
 * the compute-unit limit. Rounds up, and charges an absent limit at the runtime
 * maximum.
 */
function effectivePriorityFeeLamports(fee: ManualFeeInstructions): bigint {
    const price = fee.price ?? 0n;
    const limit = BigInt(fee.limit ?? MAX_COMPUTE_UNIT_LIMIT);
    return (price * limit + MICRO_LAMPORTS_PER_LAMPORT - 1n) / MICRO_LAMPORTS_PER_LAMPORT;
}

/** `undefined` when a custom `priority_fee` already bounds the total. */
function manualPriorityFeeCeiling(policy: ManualFeePolicy): bigint | undefined {
    if (policy.maxPriorityFeeLamports !== undefined) return policy.maxPriorityFeeLamports;
    if (policy.fee?.type === 'custom' && policy.fee.priority_fee !== undefined) return undefined;
    return DEFAULT_MAX_PRIORITY_FEE_LAMPORTS;
}

/** Enforces {@link DEFAULT_MAX_PRIORITY_FEE_LAMPORTS} or the configured override. */
function validateManualFeeCeiling(policy: ManualFeePolicy, returned: ManualFeeInstructions): void {
    if (returned.price === undefined) return;
    const ceiling = manualPriorityFeeCeiling(policy);
    if (ceiling === undefined) return;
    if (effectivePriorityFeeLamports(returned) > ceiling) {
        throw new Error(
            'Fordefi returned a priority fee above the configured maximum; raise maxPriorityFeeLamports to allow it',
        );
    }
}

function validateManualCustomFee(fee: FordefiSolanaFee | undefined, returned: ManualFeeInstructions): void {
    if (fee?.type !== 'custom') return;
    if (fee.unit_price !== undefined) {
        const configuredPrice = BigInt(fee.unit_price);
        if (returned.price === undefined || returned.price !== configuredPrice) {
            throw new Error(
                'Fordefi returned a compute-unit price that does not match the configured custom unit_price',
            );
        }
    }
    if (fee.priority_fee !== undefined && returned.price !== undefined) {
        if (effectivePriorityFeeLamports(returned) > BigInt(fee.priority_fee)) {
            throw new Error('Fordefi returned a priority fee above the configured custom priority_fee');
        }
    }
}

/** Validate the mutation set Fordefi documents for an unsigned native manual request. */
export async function manualMessagesMatchFordefiMutationPolicy(
    originalMessageBytes: Uint8Array,
    returnedMessageBytes: Uint8Array,
    policy: ManualFeePolicy,
): Promise<boolean> {
    const decoder = getCompiledTransactionMessageDecoder();
    const original = decoder.decode(originalMessageBytes);
    const returned = decoder.decode(returnedMessageBytes);
    if (original.version !== returned.version) {
        return false;
    }
    const originalLifetime = await getTransactionLifetimeConstraintFromCompiledTransactionMessage(original);
    if ('nonce' in originalLifetime) {
        if (!bytesEqual(originalMessageBytes, returnedMessageBytes)) return false;
        if (original.version !== 1) {
            validateManualCustomFee(policy.fee, normalizeManualFeeMessage(original).fees);
        }
        return true;
    }
    // The second clause is unreachable (the versions were proven equal above)
    // but is what narrows `returned` for the legacy/v0 path below.
    if (original.version === 1 || returned.version === 1) {
        return compareManualMessagesExactly(original, returned, true);
    }

    const normalizedOriginal = normalizeManualFeeMessage(original);
    if (normalizedOriginal.fees.price !== undefined) {
        if (!compareManualMessagesExactly(original, returned, true)) return false;
        validateManualCustomFee(policy.fee, normalizedOriginal.fees);
        return true;
    }
    const normalizedReturned = normalizeManualFeeMessage(returned);
    // The caller set no compute-unit price, so any price here is Fordefi's own
    // and is bounded by the absolute ceiling as well as any custom fee config.
    validateManualFeeCeiling(policy, normalizedReturned.fees);
    validateManualCustomFee(policy.fee, normalizedReturned.fees);
    const comparableReturned = {
        ...normalizedReturned.message,
        lifetimeToken: normalizedOriginal.message.lifetimeToken,
    } as LegacyOrV0CompiledMessage;
    return bytesEqual(encodeCompiledMessage(normalizedOriginal.message), encodeCompiledMessage(comparableReturned));
}
