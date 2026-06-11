import { afterEach, describe, expect, it, vi } from 'vitest';

import { signBatchStaggered, validateRequestDelayMs } from '../batch.js';

describe('validateRequestDelayMs', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('accepts zero and positive values', () => {
        expect(() => validateRequestDelayMs(0)).not.toThrow();
        expect(() => validateRequestDelayMs(500)).not.toThrow();
    });

    it('throws CONFIG_ERROR for negative values', () => {
        expect(() => validateRequestDelayMs(-1)).toThrow('requestDelayMs must not be negative');
    });

    it('warns for values above 3000ms', () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        validateRequestDelayMs(5000);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('requestDelayMs is greater than 3000ms'));
    });
});

describe('signBatchStaggered', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('signs all items in order with no delay', async () => {
        const results = await signBatchStaggered([1, 2, 3], async (item, index) => item * 10 + index, 0);
        expect(results).toEqual([10, 21, 32]);
    });

    it('staggers each item by index * delayMs', async () => {
        vi.useFakeTimers();
        const started: number[] = [];

        const promise = signBatchStaggered(
            ['a', 'b', 'c'],
            async (_item, index) => {
                started.push(index);
                return index;
            },
            100,
        );

        await vi.advanceTimersByTimeAsync(0);
        expect(started).toEqual([0]);
        await vi.advanceTimersByTimeAsync(100);
        expect(started).toEqual([0, 1]);
        await vi.advanceTimersByTimeAsync(100);
        expect(started).toEqual([0, 1, 2]);

        await expect(promise).resolves.toEqual([0, 1, 2]);
    });

    it('rejects when any item fails', async () => {
        await expect(
            signBatchStaggered(
                [1, 2],
                async item => {
                    if (item === 2) throw new Error('nope');
                    return item;
                },
                0,
            ),
        ).rejects.toThrow('nope');
    });
});
