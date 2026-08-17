import type { Address } from '@solana/addresses';
import { describe, expect, it } from 'vitest';

import { isSolanaSendingSigner, isSolanaSigner } from '../utils.js';

const ADDRESS = '11111111111111111111111111111111' as Address;

const partialSigner = {
    address: ADDRESS,
    isAvailable: async () => true,
    signMessages: async () => [],
    signTransactions: async () => [],
};

const sendingSigner = {
    address: ADDRESS,
    isAvailable: async () => true,
    signAndSendTransactions: async () => [],
};

describe('isSolanaSigner', () => {
    it('accepts a partial signer', () => {
        expect(isSolanaSigner(partialSigner)).toBe(true);
    });

    it('rejects a sending-only signer', () => {
        expect(isSolanaSigner(sendingSigner)).toBe(false);
    });
});

describe('isSolanaSendingSigner', () => {
    it('accepts a sending signer', () => {
        expect(isSolanaSendingSigner(sendingSigner)).toBe(true);
    });

    it('rejects a partial signer', () => {
        expect(isSolanaSendingSigner(partialSigner)).toBe(false);
    });

    it('rejects a signer without isAvailable', () => {
        const { isAvailable: _unused, ...withoutIsAvailable } = sendingSigner;
        expect(isSolanaSendingSigner(withoutIsAvailable as never)).toBe(false);
    });
});
