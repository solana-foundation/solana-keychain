import { anyAbortSignal } from './abort.js';
import { sanitizeRemoteErrorResponse, SignerError, SignerErrorCode, throwSignerError } from './errors.js';

/** Default timeout applied to remote signer API requests. */
export const DEFAULT_FETCH_TIMEOUT_MS = 60_000;

export interface FetchSignerJsonOptions {
    /**
     * Caller-supplied cancellation, typically the `abortSignal` of a Kit signer
     * config. It composes with the timeout: whichever fires first aborts the
     * request. When it has already fired, no request is made at all and the
     * abort reason is thrown unwrapped rather than as a signer error.
     */
    abortSignal?: AbortSignal;
    /**
     * Standard fetch options (method, headers, body, ...).
     *
     * A `signal` here is the raw escape hatch for callers that own the whole
     * request lifetime: it replaces the timeout instead of composing with it,
     * and still composes with {@link FetchSignerJsonOptions.abortSignal}.
     * Prefer {@link FetchSignerJsonOptions.abortSignal} for cancellation.
     */
    init?: RequestInit;
    /** Human-readable provider name used in error messages (e.g. "Privy"). */
    providerName: string;
    /**
     * Per-request timeout in ms. Ignored when `init.signal` is provided.
     * Default: {@link DEFAULT_FETCH_TIMEOUT_MS}.
     */
    timeoutMs?: number;
    /** Fully-qualified request URL. */
    url: string;
}

/** The provider's HTTP status when its response was the failure. */
export function providerStatus(error: unknown): number | undefined {
    const status = error instanceof SignerError ? error.context?.status : undefined;
    return typeof status === 'number' ? status : undefined;
}

/**
 * A 4xx is the only create outcome that rules out a transaction; anything else
 * (no response, timeout, 5xx, unusable success body) may already be executing.
 */
export function providerMayHaveAccepted(error: unknown): boolean {
    const status = providerStatus(error);
    return status === undefined || status < 400 || status >= 500;
}

/**
 * Perform a remote signer API request and parse the JSON response, mapping
 * failures to the standard signer error pipeline:
 * - network failure or timeout → `HTTP_ERROR`
 * - non-2xx status → `REMOTE_API_ERROR` with the sanitized response body
 * - invalid JSON body → `PARSING_ERROR`
 *
 * Redirects are always rejected and every request carries a timeout unless
 * the caller supplies its own `init.signal`. A caller `abortSignal` propagates
 * its abort reason unwrapped, so cancellation is distinguishable from failure.
 *
 * A non-2xx response is the one exception: the provider has already returned
 * its verdict, and that verdict is what callers classify broadcast safety on
 * (a 4xx rules the transaction out, an abort reason does not). Such a response
 * surfaces as `REMOTE_API_ERROR` carrying the status even when the caller
 * aborts while the error body is being read.
 */
export async function fetchSignerJson<TResponse>(options: FetchSignerJsonOptions): Promise<TResponse> {
    const { abortSignal, init = {}, providerName, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS, url } = options;

    abortSignal?.throwIfAborted();

    const signals: AbortSignal[] = [];
    if (abortSignal) signals.push(abortSignal);
    signals.push(init.signal ?? AbortSignal.timeout(timeoutMs));

    let response: Response;
    try {
        response = await fetch(url, {
            ...init,
            redirect: 'error',
            signal: anyAbortSignal(signals),
        });
    } catch (error) {
        abortSignal?.throwIfAborted();
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: `${providerName} network request failed`,
            url,
        });
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `${providerName} API error: ${response.status}`,
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    try {
        return (await response.json()) as TResponse;
    } catch (error) {
        abortSignal?.throwIfAborted();
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: `Failed to parse ${providerName} response`,
        });
    }
}
