import type { Address } from '@solana/addresses';
import { describe, expect, it } from 'vitest';

import {
    assertIsSolanaTransactionSigner,
    isSolanaMessageSigner,
    isSolanaModifyingSigner,
    isSolanaSendingSigner,
    isSolanaSigner,
    isSolanaTransactionSigner,
    signerCapabilities,
} from '../utils.js';

const ADDRESS = '11111111111111111111111111111111' as Address;

const partialSigner = {
    address: ADDRESS,
    isAvailable: async () => true,
    signMessages: async () => [],
    signTransactions: async () => [],
};

const modifyingSigner = {
    address: ADDRESS,
    isAvailable: async () => true,
    modifyAndSignTransactions: async () => [],
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

    it('accepts a modifying signer', () => {
        expect(isSolanaSigner(modifyingSigner)).toBe(true);
    });

    it('accepts a sending-only signer', () => {
        expect(isSolanaSigner(sendingSigner)).toBe(true);
    });

    it('rejects a value without a signing method', () => {
        expect(isSolanaSigner({ address: ADDRESS, isAvailable: async () => true })).toBe(false);
    });
});

describe('isSolanaTransactionSigner', () => {
    it('accepts a partial signer', () => {
        expect(isSolanaTransactionSigner(partialSigner)).toBe(true);
    });

    it('rejects a modifying signer', () => {
        expect(isSolanaTransactionSigner(modifyingSigner)).toBe(false);
    });

    it('rejects a sending signer', () => {
        expect(isSolanaTransactionSigner(sendingSigner)).toBe(false);
    });
});

describe('isSolanaModifyingSigner', () => {
    it('accepts a modifying signer', () => {
        expect(isSolanaModifyingSigner(modifyingSigner)).toBe(true);
    });

    it('rejects a partial signer', () => {
        expect(isSolanaModifyingSigner(partialSigner)).toBe(false);
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

describe('isSolanaMessageSigner', () => {
    it('accepts a signer exposing signMessages', () => {
        expect(isSolanaMessageSigner(partialSigner)).toBe(true);
    });

    it('rejects a signer without signMessages', () => {
        expect(isSolanaMessageSigner(sendingSigner)).toBe(false);
    });
});

describe('assertIsSolanaTransactionSigner', () => {
    it('passes a partial signer through', () => {
        expect(() => assertIsSolanaTransactionSigner(partialSigner)).not.toThrow();
    });

    it('throws EXPECTED_SOLANA_SIGNER for a sending signer', () => {
        expect(() => assertIsSolanaTransactionSigner(sendingSigner)).toThrow(/EXPECTED_SOLANA_SIGNER/);
    });
});

describe('signerCapabilities', () => {
    it('reports the methods a partial signer exposes', () => {
        expect(signerCapabilities(partialSigner)).toStrictEqual({
            canModifyTransactions: false,
            canSignAndSend: false,
            canSignMessages: true,
            canSignTransactions: true,
        });
    });

    it('reports the methods a modifying signer exposes', () => {
        expect(signerCapabilities(modifyingSigner)).toStrictEqual({
            canModifyTransactions: true,
            canSignAndSend: false,
            canSignMessages: false,
            canSignTransactions: false,
        });
    });

    it('reports the methods a sending signer exposes', () => {
        expect(signerCapabilities(sendingSigner)).toStrictEqual({
            canModifyTransactions: false,
            canSignAndSend: true,
            canSignMessages: false,
            canSignTransactions: false,
        });
    });
});
