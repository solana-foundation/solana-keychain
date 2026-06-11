import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeJwt } from 'jose';

import { createJwt, importFireblocksPrivateKey } from '../jwt.js';
import { TEST_API_KEY, TEST_RSA_PRIVATE_KEY } from './setup.js';

const JWT_TTL_SECS = 120;
const JWT_SKEW_LEEWAY_SECS = 60;

describe('importFireblocksPrivateKey', () => {
    it('imports a valid PKCS8 PEM key', async () => {
        const key = await importFireblocksPrivateKey(TEST_RSA_PRIVATE_KEY);
        expect(key).toBeDefined();
    });

    it('throws INVALID_PRIVATE_KEY for an unparseable PEM', async () => {
        await expect(importFireblocksPrivateKey('not-a-pem')).rejects.toMatchObject({
            code: 'SIGNER_INVALID_PRIVATE_KEY',
            message: expect.stringContaining('Failed to parse Fireblocks RSA private key'),
        });
    });
});

describe('createJwt', () => {
    let privateKey: CryptoKey;

    beforeAll(async () => {
        privateKey = await importFireblocksPrivateKey(TEST_RSA_PRIVATE_KEY);
    });

    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it('sets clock-skew tolerant timing claims', async () => {
        const nowMs = 1_700_000_000_000;
        const nowSec = Math.floor(nowMs / 1000);
        vi.spyOn(Date, 'now').mockReturnValue(nowMs);

        const token = await createJwt(TEST_API_KEY, privateKey, '/v1/test', '{"hello":"world"}');
        const payload = decodeJwt(token);

        expect(payload.iat).toBe(nowSec - JWT_SKEW_LEEWAY_SECS);
        expect(payload.nbf).toBe(nowSec - JWT_SKEW_LEEWAY_SECS);
        expect(payload.exp).toBe(nowSec + JWT_TTL_SECS);
    });

    it('includes expected claims for Fireblocks auth', async () => {
        const token = await createJwt(TEST_API_KEY, privateKey, '/v1/transactions', '');
        const payload = decodeJwt(token);

        expect(payload.sub).toBe(TEST_API_KEY);
        expect(payload.uri).toBe('/v1/transactions');
        expect(typeof payload.nonce).toBe('string');
        expect(typeof payload.bodyHash).toBe('string');
        expect((payload.bodyHash as string).length).toBe(64);
    });
});
