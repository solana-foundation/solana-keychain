/**
 * `AbortSignal.any` with a fallback for runtimes that lack it
 * (`AbortSignal.any` requires Node.js >= 20.3; the package supports >= 18).
 */
export function anyAbortSignal(signals: readonly AbortSignal[]): AbortSignal {
    if (signals.length === 1) {
        return signals[0]!;
    }
    if (typeof AbortSignal.any === 'function') {
        return AbortSignal.any([...signals]);
    }
    const controller = new AbortController();
    for (const signal of signals) {
        if (signal.aborted) {
            controller.abort(signal.reason);
            break;
        }
        signal.addEventListener('abort', () => controller.abort(signal.reason), {
            once: true,
            signal: controller.signal,
        });
    }
    return controller.signal;
}

/** Resolve after `ms`, or reject with the abort reason as soon as `abortSignal` fires. */
export async function abortableDelay(ms: number, abortSignal?: AbortSignal): Promise<void> {
    abortSignal?.throwIfAborted();
    if (!abortSignal) {
        await new Promise<void>(resolve => setTimeout(resolve, ms));
        return;
    }
    const signal = abortSignal;
    await new Promise<void>(resolve => {
        const timer = setTimeout(() => {
            signal.removeEventListener('abort', onAbort);
            resolve();
        }, ms);
        function onAbort() {
            clearTimeout(timer);
            resolve();
        }
        signal.addEventListener('abort', onAbort, { once: true });
    });
    signal.throwIfAborted();
}
