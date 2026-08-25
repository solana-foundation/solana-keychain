import type { Address } from '@solana/addresses';
import { describe, expect, it } from 'vitest';

import { isSolanaModifyingSigner, isSolanaSendingSigner, isSolanaSigner, signerCapabilities } from '../utils.js';

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

const modifyingSigner = {
    address: ADDRESS,
    isAvailable: async () => true,
    modifyAndSignTransactions: async () => [],
};

describe('isSolanaSigner', () => {
    it('accepts a partial signer', () => {
        expect(isSolanaSigner(partialSigner)).toBe(true);
    });

    it('rejects a sending-only signer', () => {
        expect(isSolanaSigner(sendingSigner)).toBe(false);
    });

    it('rejects a modifying-only signer', () => {
        expect(isSolanaSigner(modifyingSigner)).toBe(false);
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

describe('isSolanaModifyingSigner', () => {
    it('accepts a modifying signer', () => {
        expect(isSolanaModifyingSigner(modifyingSigner)).toBe(true);
    });

    it('rejects a partial signer', () => {
        expect(isSolanaModifyingSigner(partialSigner)).toBe(false);
    });

    it('rejects a sending signer', () => {
        expect(isSolanaModifyingSigner(sendingSigner)).toBe(false);
    });

    it('rejects a signer without isAvailable', () => {
        const { isAvailable: _unused, ...withoutIsAvailable } = modifyingSigner;
        expect(isSolanaModifyingSigner(withoutIsAvailable as never)).toBe(false);
    });
});

describe('signerCapabilities', () => {
    it('reports the methods a partial signer exposes', () => {
        expect(signerCapabilities(partialSigner)).toStrictEqual({
            canModifyAndSignTransactions: false,
            canSignAndSend: false,
            canSignMessages: true,
            canSignTransactions: true,
        });
    });

    it('reports the methods a sending signer exposes', () => {
        expect(signerCapabilities(sendingSigner)).toStrictEqual({
            canModifyAndSignTransactions: false,
            canSignAndSend: true,
            canSignMessages: false,
            canSignTransactions: false,
        });
    });

    it('reports the methods a modifying signer exposes', () => {
        expect(signerCapabilities(modifyingSigner)).toStrictEqual({
            canModifyAndSignTransactions: true,
            canSignAndSend: false,
            canSignMessages: false,
            canSignTransactions: false,
        });
    });
});
