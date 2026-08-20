import { sanitizeRemoteErrorResponse, SignerError, SignerErrorCode, throwSignerError } from './errors.js';

/** Default timeout applied to remote signer API requests. */
export const DEFAULT_FETCH_TIMEOUT_MS = 60_000;

export interface FetchSignerJsonOptions {
    /** Standard fetch options (method, headers, body, signal, ...). */
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

/**
 * The provider's own HTTP status when its response was the failure, and
 * `undefined` when no response arrived or its body was the problem.
 */
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
 * the caller supplies its own `AbortSignal`.
 */
export async function fetchSignerJson<TResponse>(options: FetchSignerJsonOptions): Promise<TResponse> {
    const { init = {}, providerName, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS, url } = options;

    let response: Response;
    try {
        response = await fetch(url, {
            ...init,
            redirect: 'error',
            signal: init.signal ?? AbortSignal.timeout(timeoutMs),
        });
    } catch (error) {
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
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: `Failed to parse ${providerName} response`,
        });
    }
}
