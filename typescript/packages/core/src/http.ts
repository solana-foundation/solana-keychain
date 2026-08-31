import { anyAbortSignal } from './abort.js';
import {
    createSignerError,
    sanitizeRemoteErrorResponse,
    SignerError,
    SignerErrorCode,
    throwSignerError,
} from './errors.js';

/** Default timeout applied to remote signer API requests. */
export const DEFAULT_FETCH_TIMEOUT_MS = 60_000;

/**
 * Maximum number of response-body bytes accepted from a remote signer API
 * (1 MiB, matching the Go backend). Larger bodies fail with `PARSING_ERROR`
 * instead of being buffered unbounded.
 */
export const MAX_RESPONSE_BYTES = 1024 * 1024;

const providerResponseErrors = new WeakSet<SignerError>();

function throwProviderResponseError(code: SignerErrorCode, context: Record<string, unknown>): never {
    const error = createSignerError(code, context);
    providerResponseErrors.add(error);
    throw error;
}

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
    const status =
        error instanceof SignerError && providerResponseErrors.has(error) ? error.context?.status : undefined;
    return typeof status === 'number' ? status : undefined;
}

/**
 * A 4xx other than 408 is the only create outcome that rules out a transaction;
 * anything else (no response, timeout, 5xx, unusable success body) may already be
 * executing. A 408 is a timeout reached while the request was being processed, so
 * it does not rule the transaction out either.
 */
export function providerMayHaveAccepted(error: unknown): boolean {
    const status = providerStatus(error);
    return status === undefined || status < 400 || status >= 500 || status === 408;
}

function throwResponseTooLarge(providerName: string, status: number): never {
    throwProviderResponseError(SignerErrorCode.PARSING_ERROR, {
        maxResponseBytes: MAX_RESPONSE_BYTES,
        message: `${providerName} response exceeded maximum size`,
        status,
    });
}

/**
 * Read a response body as text while enforcing {@link MAX_RESPONSE_BYTES}.
 *
 * A `Content-Length` header over the cap fails fast, but the cap is always
 * enforced while streaming too (the header can lie or be absent). Returns
 * `undefined` when the response exposes no readable body stream, so callers
 * can fall back to the non-streaming read.
 */
async function readCappedResponseText(response: Response, providerName: string): Promise<string | undefined> {
    const contentLength = Number(response.headers?.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
        throwResponseTooLarge(providerName, response.status);
    }

    const body = response.body;
    if (!body) {
        return undefined;
    }

    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value) continue;
            totalBytes += value.byteLength;
            if (totalBytes > MAX_RESPONSE_BYTES) {
                throwResponseTooLarge(providerName, response.status);
            }
            chunks.push(value);
        }
    } finally {
        await reader.cancel().catch(() => {});
    }

    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
}

/**
 * The top-level `id` of a failed response body, when there is one. A provider
 * that has already accepted a transaction may still answer with a non-2xx
 * status, and that id is the caller's only handle for reconciling it.
 */
function transactionIdInBody(body: string): string | undefined {
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        return undefined;
    }
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    const transactionId = (parsed as { id?: unknown }).id;
    return typeof transactionId === 'string' && transactionId.trim() ? transactionId : undefined;
}

/**
 * Perform a remote signer API request and parse the JSON response, mapping
 * failures to the standard signer error pipeline:
 * - network failure or timeout → `HTTP_ERROR`
 * - non-2xx status → `REMOTE_API_ERROR` with the sanitized response body
 * - invalid JSON body → `PARSING_ERROR`
 * - body over {@link MAX_RESPONSE_BYTES} → `PARSING_ERROR`
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
        let errorText: string;
        try {
            errorText = (await readCappedResponseText(response, providerName)) ?? (await response.text());
        } catch (error) {
            // An over-cap body is a hard failure; any other read failure keeps
            // the provider's verdict with a placeholder body.
            if (error instanceof SignerError) throw error;
            errorText = 'Failed to read error response';
        }
        const providerTransactionId = transactionIdInBody(errorText);
        throwProviderResponseError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `${providerName} API error: ${response.status}`,
            ...(providerTransactionId === undefined ? {} : { providerTransactionId }),
            response: sanitizeRemoteErrorResponse(errorText),
            status: response.status,
        });
    }

    try {
        const text = await readCappedResponseText(response, providerName);
        return (text === undefined ? await response.json() : JSON.parse(text)) as TResponse;
    } catch (error) {
        // The over-cap error is already a fully-classified PARSING_ERROR.
        if (error instanceof SignerError) throw error;
        abortSignal?.throwIfAborted();
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: `Failed to parse ${providerName} response`,
        });
    }
}
