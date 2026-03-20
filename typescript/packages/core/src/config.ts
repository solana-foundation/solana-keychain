import { SignerErrorCode, throwSignerError } from './errors.js';

/**
 * Validate that `requestDelayMs` is non-negative.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when the value is negative.
 */
function validateRequestDelayMs(requestDelayMs: number): void {
    if (requestDelayMs < 0) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'requestDelayMs must not be negative',
        });
    }
    if (requestDelayMs > 3000) {
        console.warn(
            `[solana-keychain] requestDelayMs is ${requestDelayMs}ms. High values may cause transaction blockhash expiration.`,
        );
    }
}

/**
 * Create a delay function bound to a specific `requestDelayMs` value.
 *
 * Returns a function that, given a batch index, sleeps for `index * delayMs`
 * milliseconds. Index 0 never sleeps.
 *
 * @param delayMs - The per-item delay in milliseconds (0 = no delay).
 */
export function createBatchDelay(delayMs: number): (index: number) => Promise<void> {
    validateRequestDelayMs(delayMs);
    return async (index: number): Promise<void> => {
        if (delayMs > 0 && index > 0) {
            await new Promise(resolve => setTimeout(resolve, index * delayMs));
        }
    };
}
