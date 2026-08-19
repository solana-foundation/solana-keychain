import { describe, expect, it } from 'vitest';

import { idempotencyKeyFromMessage } from '../utils.js';

const UUID_V4_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('idempotencyKeyFromMessage', () => {
    it('derives a deterministic version-4-shaped UUID from the message bytes', async () => {
        const message = new Uint8Array([1, 2, 3]);
        const key = await idempotencyKeyFromMessage(message);
        expect(key).toMatch(UUID_V4_SHAPE);
        expect(await idempotencyKeyFromMessage(message)).toBe(key);
        expect(await idempotencyKeyFromMessage(new Uint8Array([4, 5, 6]))).not.toBe(key);
    });
});
