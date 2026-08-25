import { describe, expect, it } from 'vitest';
import { getBase58Encoder } from '@solana/codecs-strings';

import {
    COMPUTE_BUDGET_PROGRAM_ADDRESS,
    decodeSetComputeUnitLimitUnits,
    decodeSetComputeUnitPriceMicroLamports,
    MAX_COMPUTE_UNIT_LIMIT,
    SET_COMPUTE_UNIT_LIMIT_DATA_LENGTH,
    SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR,
    SET_COMPUTE_UNIT_PRICE_DATA_LENGTH,
    SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR,
} from '../compute-budget.js';

// Pins the locally declared Compute Budget facts to their canonical values,
// mirroring the Rust crate's sdk_adapter tests for the same constants.
describe('compute budget constants', () => {
    it('matches the canonical program id bytes', () => {
        // 'ComputeBudget111111111111111111111111111111' base58-decoded.
        const canonicalBytes = new Uint8Array([
            3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187, 197, 247, 18,
            107, 44, 67, 155, 58, 64, 0, 0, 0,
        ]);
        expect(new Uint8Array(getBase58Encoder().encode(COMPUTE_BUDGET_PROGRAM_ADDRESS))).toStrictEqual(canonicalBytes);
    });

    it('matches the canonical instruction layouts', () => {
        expect(SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR).toBe(2);
        expect(SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR).toBe(3);
        expect(SET_COMPUTE_UNIT_LIMIT_DATA_LENGTH).toBe(5);
        expect(SET_COMPUTE_UNIT_PRICE_DATA_LENGTH).toBe(9);
        expect(MAX_COMPUTE_UNIT_LIMIT).toBe(1_400_000);
    });

    it('decodes SetComputeUnitLimit units little-endian after the discriminator', () => {
        const data = new Uint8Array([SET_COMPUTE_UNIT_LIMIT_DISCRIMINATOR, 0x40, 0x0d, 0x03, 0x00]);
        expect(decodeSetComputeUnitLimitUnits(data)).toBe(200_000);
    });

    it('decodes SetComputeUnitPrice micro-lamports little-endian after the discriminator', () => {
        const data = new Uint8Array([
            SET_COMPUTE_UNIT_PRICE_DISCRIMINATOR,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
        ]);
        expect(decodeSetComputeUnitPriceMicroLamports(data)).toBe(2n ** 64n - 1n);
    });
});
