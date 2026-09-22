import { getBase64Decoder } from '@solana/codecs-strings';
import { describe, expect, it } from 'vitest';

import { normalizeMessageBytes } from '../utils.js';

const PAYLOAD = new Uint8Array([1, 2, 3, 4, 5]);

function sharedOffsetView(bytes: Uint8Array) {
    const shared = new Uint8Array(new SharedArrayBuffer(bytes.length + 8));
    shared.set(bytes, 8);
    return shared.subarray(8);
}

describe('normalizeMessageBytes', () => {
    it('copies the bytes instead of aliasing the caller-owned buffer', () => {
        const source = PAYLOAD.slice();
        const normalized = normalizeMessageBytes(source);
        source[0] = 99;
        expect(normalized).toStrictEqual(PAYLOAD);
    });

    it('copies a shared, offset view into an owned zero-offset buffer', () => {
        const view = sharedOffsetView(PAYLOAD);
        const normalized = normalizeMessageBytes(view);
        expect(normalized).toStrictEqual(PAYLOAD);
        expect(normalized.byteOffset).toBe(0);
        expect(normalized.buffer).toBeInstanceOf(ArrayBuffer);
        expect(getBase64Decoder().decode(normalized)).toBe(getBase64Decoder().decode(PAYLOAD));
    });

    it('copies a Node.js Buffer instead of returning a view over its memory', () => {
        const source = Buffer.from(PAYLOAD);
        const normalized = normalizeMessageBytes(source);
        expect(normalized).not.toBeInstanceOf(Buffer);
        expect(normalized.buffer).not.toBe(source.buffer);
        source[0] = 99;
        expect(normalized).toStrictEqual(PAYLOAD);
    });

    it('materializes an ArrayLike that is not a typed array', () => {
        expect(normalizeMessageBytes({ 0: 1, 1: 2, 2: 3, length: 3 })).toStrictEqual(new Uint8Array([1, 2, 3]));
    });
});
