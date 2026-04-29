import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { loadKeypairFile, parsePrivateKeyString } from '../keypair-util.js';

const TEST_KEYPAIR_BYTES_STRING =
    '[41,99,180,88,51,57,48,80,61,63,219,75,176,49,116,254,227,176,196,204,122,47,166,133,155,252,217,0,253,17,49,143,47,94,121,167,195,136,72,22,157,48,77,88,63,96,57,122,181,243,236,188,241,134,174,224,100,246,17,170,104,17,151,48]';
const TEST_KEYPAIR_BASE58 = 'pzjkwgQ5shhq3Awijz6CjDjZrXPX7YKKgkTipBK7JAq8XW5GbDynBFChESMBrz4SvFiZ8qJAtUB6sL3PpVCnbR1';
const TEST_KEYPAIR_BYTES = new Uint8Array([
    41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196, 204, 122, 47, 166, 133, 155,
    252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136, 72, 22, 157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236,
    188, 241, 134, 174, 224, 100, 246, 17, 170, 104, 17, 151, 48,
]);

async function tmpFile(content: string): Promise<string> {
    const path = join(tmpdir(), `solana-keychain-memory-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    await writeFile(path, content, 'utf-8');
    return path;
}

describe('parsePrivateKeyString', () => {
    it('auto-detects U8Array format', () => {
        const bytes = parsePrivateKeyString(TEST_KEYPAIR_BYTES_STRING);
        expect(bytes).toEqual(TEST_KEYPAIR_BYTES);
    });

    it('auto-detects base58 format', () => {
        const bytes = parsePrivateKeyString(TEST_KEYPAIR_BASE58);
        expect(bytes).toEqual(TEST_KEYPAIR_BYTES);
    });

    it('rejects malformed U8Array strings', () => {
        expect(() => parsePrivateKeyString('[not,a,number]')).toThrow('Invalid U8Array private key format');
    });

    it('rejects base58 keys with the wrong decoded length', () => {
        expect(() => parsePrivateKeyString('1111')).toThrow(/Invalid private key length/);
    });
});

describe('loadKeypairFile', () => {
    it('reads and parses a Solana CLI keypair file', async () => {
        const path = await tmpFile(TEST_KEYPAIR_BYTES_STRING);
        const bytes = await loadKeypairFile(path);
        expect(bytes).toEqual(TEST_KEYPAIR_BYTES);
    });

    it('throws SIGNER_IO_ERROR when the file is missing', async () => {
        const missing = join(tmpdir(), `solana-keychain-memory-missing-${Date.now()}.json`);
        await expect(loadKeypairFile(missing)).rejects.toThrow('Failed to read private key file');
    });

    it('throws when the file content is malformed', async () => {
        const path = await tmpFile('not a json keypair');
        await expect(loadKeypairFile(path)).rejects.toThrow('Invalid JSON keypair format');
    });
});
