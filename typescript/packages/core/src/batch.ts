import { SignerErrorCode, throwSignerError } from './errors.js';

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
 */
export async function signBatchStaggered<TItem, TResult>(
    items: readonly TItem[],
    fn: (item: TItem, index: number) => Promise<TResult>,
    delayMs: number,
): Promise<readonly TResult[]> {
    return await Promise.all(
        items.map(async (item, index) => {
            if (delayMs > 0 && index > 0) {
                await new Promise(resolve => setTimeout(resolve, index * delayMs));
            }
            return await fn(item, index);
        }),
    );
}
