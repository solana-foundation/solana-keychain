import { abortableDelay } from './abort.js';
import { createSignerError, SignerError, SignerErrorCode, throwSignerError } from './errors.js';

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
 * Signs items sequentially so completed provider-side work is retained on failure.
 *
 * Any failure, including an abort, is reported as a `SignerError` whose context
 * carries the results completed so far under `completedKey` and the index that
 * failed under `failedIndex`, so the caller knows what does not need retrying.
 * A non-`SignerError` failure is reported as `SIGNING_FAILED` with the original
 * error as `cause`.
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
        try {
            if (delayMs > 0 && index > 0) {
                await abortableDelay(delayMs, abortSignal);
            }
            abortSignal?.throwIfAborted();
            results.push(await fn(item, index));
        } catch (error) {
            const isSignerError = error instanceof SignerError;
            throw createSignerError(
                isSignerError ? error.code : SignerErrorCode.SIGNING_FAILED,
                {
                    ...(isSignerError ? error.context : { message: `Batch signing failed at index ${index}` }),
                    [completedKey]: [...results],
                    failedIndex: index,
                },
                isSignerError ? error.cause : error,
            );
        }
    }
    return results;
}
