import { describe, expect, it } from 'vitest';

import { SignerError, SignerErrorCode } from '../errors.js';
import { assertUnversionedWireTransaction } from '../utils.js';

const MAX_SIGNATURES = 12;

describe('assertUnversionedWireTransaction', () => {
    it('accepts every signature count a legacy or v0 envelope can open with', () => {
        for (let signatureCount = 1; signatureCount <= MAX_SIGNATURES; signatureCount++) {
            expect(() =>
                assertUnversionedWireTransaction({
                    providerName: 'Provider',
                    transactionBytes: new Uint8Array([signatureCount, 0, 1]),
                }),
            ).not.toThrow();
        }
    });

    it('rejects a v1 envelope, naming the provider and the version', () => {
        try {
            assertUnversionedWireTransaction({
                providerName: 'Provider',
                transactionBytes: new Uint8Array([0x81, 0x01]),
            });
            expect.unreachable('a 0x81 prefix is a v1 envelope these signature readers cannot interpret');
        } catch (error) {
            expect(error).toBeInstanceOf(SignerError);
            expect((error as SignerError).code).toBe(SignerErrorCode.SERIALIZATION_ERROR);
            expect((error as SignerError).context?.message).toContain('Provider');
            expect((error as SignerError).context?.message).toContain('v1');
        }
    });

    it('defers to the decoder for empty bytes', () => {
        expect(() =>
            assertUnversionedWireTransaction({ providerName: 'Provider', transactionBytes: new Uint8Array() }),
        ).not.toThrow();
    });
});
