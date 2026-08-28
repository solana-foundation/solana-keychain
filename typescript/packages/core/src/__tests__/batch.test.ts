import { afterEach, describe, expect, it, vi } from 'vitest';

import { signBatchSequential, signBatchStaggered, validateRequestDelayMs } from '../batch.js';
import { SignerError, SignerErrorCode, throwSignerError } from '../errors.js';

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

    it('rejects with the abort reason for an already-aborted signal without calling fn', async () => {
        const reason = new Error('already cancelled');
        const fn = vi.fn(async (item: number) => item);

        await expect(signBatchStaggered([1, 2], fn, 0, AbortSignal.abort(reason))).rejects.toBe(reason);
        expect(fn).not.toHaveBeenCalled();
    });

    it('cancels the pending stagger delay and rejects with the abort reason', async () => {
        vi.useFakeTimers();
        const controller = new AbortController();
        const reason = new Error('cancelled mid-batch');
        const started: number[] = [];

        const promise = signBatchStaggered(
            ['a', 'b', 'c'],
            async (_item, index) => {
                started.push(index);
                return index;
            },
            100,
            controller.signal,
        );
        const rejects = expect(promise).rejects.toBe(reason);

        await vi.advanceTimersByTimeAsync(0);
        expect(started).toEqual([0]);

        controller.abort(reason);
        await rejects;

        await vi.advanceTimersByTimeAsync(500);
        expect(started).toEqual([0]);
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

describe('signBatchSequential', () => {
    it('signs items one at a time, never starting one before the previous finishes', async () => {
        const inFlight: number[] = [];
        let concurrent = 0;

        const results = await signBatchSequential(
            [1, 2, 3],
            async (item, index) => {
                concurrent += 1;
                inFlight.push(concurrent);
                await Promise.resolve();
                concurrent -= 1;
                return item * 10 + index;
            },
            0,
            'completedSignatures',
        );

        expect(results).toEqual([10, 21, 32]);
        expect(inFlight).toEqual([1, 1, 1]);
    });

    it('submits nothing past the failure and reports what completed', async () => {
        const attempted: number[] = [];

        const error = await signBatchSequential(
            [1, 2, 3],
            async item => {
                attempted.push(item);
                if (item === 2) {
                    throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        message: 'unresolved',
                        providerTransactionId: 'tx-2',
                    });
                }
                return `signed-${item}`;
            },
            0,
            'completedSignatures',
        ).then(
            () => {
                throw new Error('expected the failing item to reject');
            },
            (thrown: SignerError) => thrown,
        );

        expect(attempted).toEqual([1, 2]);
        expect(error.code).toBe('SIGNER_BROADCAST_UNCONFIRMED');
        // The failing item's own context survives alongside the batch position.
        expect(error.context).toMatchObject({
            completedSignatures: ['signed-1'],
            failedIndex: 1,
            providerTransactionId: 'tx-2',
        });
    });

    it('rethrows a non-SignerError unchanged', async () => {
        const reason = new Error('not ours');
        await expect(
            signBatchSequential(
                [1],
                () => {
                    throw reason;
                },
                0,
                'completedSignatures',
            ),
        ).rejects.toBe(reason);
    });

    it('rejects with the abort reason for an already-aborted signal without calling fn', async () => {
        const reason = new Error('already cancelled');
        const fn = vi.fn(async (item: number) => item);

        await expect(signBatchSequential([1, 2], fn, 0, 'completedSignatures', AbortSignal.abort(reason))).rejects.toBe(
            reason,
        );
        expect(fn).not.toHaveBeenCalled();
    });
});
