import { getBase64Encoder, getTransactionDecoder, getTransactionSizeLimit } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { createSignedWireTransaction } from '../wire-transaction.js';

const LEGACY_AND_V0_SIZE_LIMIT = 1232;
const V1_SIZE_LIMIT = 4096;

describe('createSignedWireTransaction', () => {
    it.each([0, 1] as const)('builds a signed v%i envelope that kit round-trips', async version => {
        const fixture = await createSignedWireTransaction(version);

        // v0 prefixes its message with 0x80, v1 with 0x81.
        expect(fixture.messageBytes[0]).toBe(version === 1 ? 0x81 : 0x80);

        const decoded = getTransactionDecoder().decode(getBase64Encoder().encode(fixture.wireTransaction));
        expect(Array.from(decoded.messageBytes)).toEqual(Array.from(fixture.messageBytes));
        expect(decoded.signatures[fixture.feePayer]).toBeDefined();
        expect(Array.from(decoded.signatures[fixture.feePayer]!)).toEqual(Array.from(fixture.signature));
    });

    it('gives a v1 transaction the larger size budget that motivates the format', async () => {
        const v0 = await createSignedWireTransaction(0);
        const v1 = await createSignedWireTransaction(1);

        const decode = (wire: (typeof v0)['wireTransaction']) =>
            getTransactionDecoder().decode(getBase64Encoder().encode(wire));

        expect(getTransactionSizeLimit(decode(v0.wireTransaction))).toBe(LEGACY_AND_V0_SIZE_LIMIT);
        expect(getTransactionSizeLimit(decode(v1.wireTransaction))).toBe(V1_SIZE_LIMIT);
    });
});
