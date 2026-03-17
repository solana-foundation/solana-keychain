import { sanitizeRemoteErrorResponse, SignerErrorCode, throwSignerError } from './errors.js';

/**
 * Performs a fetch request with consistent signer error handling.
 *
 * Wraps the standard 3-step fetch pattern used by every remote signer:
 * 1. Network request — throws `SIGNER_HTTP_ERROR` on failure
 * 2. Response status check — throws `SIGNER_REMOTE_API_ERROR` on non-2xx
 * 3. JSON parsing — throws `SIGNER_PARSING_ERROR` on malformed body
 *
 * Each signer still owns URL construction, headers, body, and response
 * shape validation after this function returns.
 *
 * @param url - The endpoint URL.
 * @param options - Standard `RequestInit` passed to `fetch()`.
 * @param label - Human-readable signer name for error messages (e.g. "Privy", "Vault").
 * @returns The parsed JSON response, cast to `T`.
 */
export async function fetchWithSignerErrors<T>(url: string, options: RequestInit, label: string): Promise<T> {
    let response: Response;
    try {
        response = await fetch(url, options);
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: `${label} network request failed`,
            url,
        });
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `${label} API error: ${response.status}`,
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    try {
        return (await response.json()) as T;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: `Failed to parse ${label} response`,
        });
    }
}
