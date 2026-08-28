import { abortableDelay } from './abort.js';
import { SignerError, SignerErrorCode, throwSignerError } from './errors.js';

const MAX_RECOMMENDED_REQUEST_DELAY_MS = 3000;

/**
 * Validate a backend's `requestDelayMs` config value.
 *
 * @throws `CONFIG_ERROR` when negative. Warns when the delay is large enough
 * to risk blockhash expiration across a staggered batch.
 */
export function validateRequestDelayMs(requestDelayMs: number): void {
    if (requestDelayMs < 0) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'requestDelayMs must not be negative',
        });
    }
    if (requestDelayMs > MAX_RECOMMENDED_REQUEST_DELAY_MS) {
        console.warn(
            'requestDelayMs is greater than 3000ms, this may result in blockhash expiration errors for signing messages/transactions',
        );
    }
}

/**
 * Run `fn` concurrently over `items`, staggering the start of each item by
 * `index * delayMs` to avoid remote API rate limits. With `delayMs` of 0 this
 * is a plain `Promise.all`.
 *
 * @param items - The messages or transactions to sign.
 * @param fn - Signer-specific function that signs one item.
 * @param delayMs - Per-index stagger in ms (a backend's `requestDelayMs`).
 * @param abortSignal - Cancels the pending stagger delays and rejects with the
 * abort reason. Items already handed to `fn` are cancelled by `fn` itself.
 */
export async function signBatchStaggered<TItem, TResult>(
    items: readonly TItem[],
    fn: (item: TItem, index: number) => Promise<TResult>,
    delayMs: number,
    abortSignal?: AbortSignal,
): Promise<readonly TResult[]> {
    abortSignal?.throwIfAborted();
    return await Promise.all(
        items.map(async (item, index) => {
            if (delayMs > 0 && index > 0) {
                await abortableDelay(index * delayMs, abortSignal);
            }
            abortSignal?.throwIfAborted();
            return await fn(item, index);
        }),
    );
}

/**
 * Run `fn` over `items` one at a time, stopping at the first rejection, for a
 * backend whose per-item work has irreversible server-side effects.
 *
 * Concurrent submission would abandon siblings the provider has already
 * accepted and may execute, so a failure in one item leaves duplicate-spend
 * risk on retry. Running in order means nothing past the failure is ever
 * submitted, and the results collected before it travel on the error under
 * `completedKey` alongside `failedIndex`: the items before the failure are
 * done, and only the failing one needs reconciling.
 *
 * @param items - The messages or transactions to sign.
 * @param fn - Signer-specific function that signs one item.
 * @param delayMs - Gap between items in ms (a backend's `requestDelayMs`).
 * @param completedKey - Error-context key the collected results are attached
 * under, naming what they are (e.g. `completedSignatures`).
 * @param abortSignal - Checked before each item; items already handed to `fn`
 * are cancelled by `fn` itself.
 */
export async function signBatchSequential<TItem, TResult>(
    items: readonly TItem[],
    fn: (item: TItem, index: number) => Promise<TResult>,
    delayMs: number,
    completedKey: string,
    abortSignal?: AbortSignal,
): Promise<readonly TResult[]> {
    abortSignal?.throwIfAborted();
    const results: TResult[] = [];
    for (const [index, item] of items.entries()) {
        if (delayMs > 0 && index > 0) {
            await abortableDelay(delayMs, abortSignal);
        }
        abortSignal?.throwIfAborted();
        try {
            results.push(await fn(item, index));
        } catch (error) {
            if (!(error instanceof SignerError)) {
                throw error;
            }
            throwSignerError(error.code, {
                ...error.context,
                [completedKey]: [...results],
                failedIndex: index,
            });
        }
    }
    return results;
}
