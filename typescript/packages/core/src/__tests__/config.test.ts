import { describe, expect, it, vi } from 'vitest';

import { createBatchDelay, validateRequestDelayMs } from '../config.js';
import { SignerErrorCode } from '../errors.js';

describe('validateRequestDelayMs', () => {
    it('accepts zero', () => {
        expect(() => validateRequestDelayMs(0)).not.toThrow();
    });

    it('accepts positive values', () => {
        expect(() => validateRequestDelayMs(100)).not.toThrow();
        expect(() => validateRequestDelayMs(5000)).not.toThrow();
    });

    it('throws CONFIG_ERROR for negative values', () => {
        expect(() => validateRequestDelayMs(-1)).toThrow('requestDelayMs must not be negative');
        try {
            validateRequestDelayMs(-1);
        } catch (error: unknown) {
            expect((error as { code: string }).code).toBe(SignerErrorCode.CONFIG_ERROR);
        }
    });
});

describe('createBatchDelay', () => {
    it('returns a function', () => {
        const delay = createBatchDelay(100);
        expect(typeof delay).toBe('function');
    });

    it('resolves immediately for index 0', async () => {
        const delay = createBatchDelay(1000);
        const start = Date.now();
        await delay(0);
        expect(Date.now() - start).toBeLessThan(50);
    });

    it('resolves immediately when delayMs is 0', async () => {
        const delay = createBatchDelay(0);
        const start = Date.now();
        await delay(5);
        expect(Date.now() - start).toBeLessThan(50);
    });

    it('delays proportional to index', async () => {
        vi.useFakeTimers();
        const delay = createBatchDelay(100);

        const promise = delay(2);
        vi.advanceTimersByTime(200);
        await promise;

        vi.useRealTimers();
    });
});
