import type { Address } from '@solana/addresses';
import { getU32Decoder, getU64Decoder } from '@solana/codecs-numbers';

// Declared locally instead of importing `@solana-program/compute-budget`: that
// client peer-requires `@solana/kit` and Node >= 24, which would raise this
// package's floor for a handful of constants. Mirrors the Rust crate, which
// declares the program ID in each `sdk_adapter/v*.rs` for the same reason.
// Everything here is pinned against canonical encodings in compute-budget.test.ts.

export const COMPUTE_BUDGET_PROGRAM_ADDRESS =
    'ComputeBudget111111111111111111111111111111' as Address<'ComputeBudget111111111111111111111111111111'>;

export const SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR = 2;
export const SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR = 3;

/** The Solana runtime's per-transaction compute-unit ceiling. */
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;

/** u8 discriminator + u32 units. */
export const SET_COMPUTE_UNIT_LIMIT_DATA_LENGTH = 5;
/** u8 discriminator + u64 micro-lamports. */
export const SET_COMPUTE_UNIT_PRICE_DATA_LENGTH = 9;

let u32Decoder: ReturnType<typeof getU32Decoder> | undefined;
let u64Decoder: ReturnType<typeof getU64Decoder> | undefined;

export function decodeSetComputeUnitLimitUnits(data: Uint8Array): number {
    u32Decoder ||= getU32Decoder();
    return u32Decoder.decode(data, 1);
}

export function decodeSetComputeUnitPriceMicroLamports(data: Uint8Array): bigint {
    u64Decoder ||= getU64Decoder();
    return u64Decoder.decode(data, 1);
}
