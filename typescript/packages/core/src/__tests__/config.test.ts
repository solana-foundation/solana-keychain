import { describe, expect, it, vi } from 'vitest';

import { createBatchDelay } from '../config.js';
import { SignerErrorCode } from '../errors.js';

describe('createBatchDelay', () => {
    it('returns a function', () => {
        const delay = createBatchDelay(100);
        expect(typeof delay).toBe('function');
    });

    it('accepts zero delayMs', () => {
        expect(() => createBatchDelay(0)).not.toThrow();
    });

    it('accepts positive delayMs', () => {
        expect(() => createBatchDelay(100)).not.toThrow();
    });

    it('throws CONFIG_ERROR for negative delayMs', () => {
        expect(() => createBatchDelay(-1)).toThrow('requestDelayMs must not be negative');
        try {
            createBatchDelay(-1);
        } catch (error: unknown) {
            expect((error as { code: string }).code).toBe(SignerErrorCode.CONFIG_ERROR);
        }
    });

    it('warns when delayMs exceeds 3000ms', () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        createBatchDelay(5000);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is 5000ms'));
        warnSpy.mockRestore();
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
