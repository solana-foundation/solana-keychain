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

    it('makes a shared, offset view encode as the bytes it holds', () => {
        // The codec mis-slices this shape and encodes only its tail, so bytes
        // that reach a codec from outside this library must be copied first.
        const view = sharedOffsetView(PAYLOAD);
        const decoder = getBase64Decoder();
        expect(decoder.decode(view)).not.toBe(decoder.decode(PAYLOAD));
        expect(decoder.decode(normalizeMessageBytes(view))).toBe(decoder.decode(PAYLOAD));
    });

    it('materializes an ArrayLike that is not a typed array', () => {
        expect(normalizeMessageBytes({ 0: 1, 1: 2, 2: 3, length: 3 })).toStrictEqual(new Uint8Array([1, 2, 3]));
    });
});
