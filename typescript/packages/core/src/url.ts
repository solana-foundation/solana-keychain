import { SignerErrorCode, throwSignerError } from './errors.js';

const LOOPBACK_HOSTNAMES = ['localhost', '127.0.0.1', '[::1]'];

/**
 * Normalize a configured base URL: trims surrounding whitespace and strips
 * all trailing slashes, so paths can be appended with a single `/`.
 */
export function normalizeBaseUrl(baseUrl: string): string {
    return baseUrl.trim().replace(/\/+$/, '');
}

export interface AssertHttpsUrlOptions {
    /**
     * Permit plain-HTTP loopback URLs (localhost / 127.0.0.1 / [::1]) when
     * `NODE_ENV=test`, for backends that run against a local dev server.
     */
    allowHttpLoopbackInTests?: boolean;
}

/**
 * Validate that a configured endpoint is a well-formed HTTPS URL and return
 * the parsed `URL`. This is the security control behind the library's
 * "HTTPS enforced" guarantee — every remote backend must run its base URL
 * through this check.
 *
 * @param url - The raw URL string from configuration.
 * @param field - Config field name used in error messages (e.g. "apiBaseUrl").
 * @throws `CONFIG_ERROR` when the URL is malformed or not HTTPS.
 */
export function assertHttpsUrl(url: string, field: string, options?: AssertHttpsUrlOptions): URL {
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(url);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: `${field} is not a valid URL`,
        });
    }

    if (parsedUrl.protocol === 'https:') {
        return parsedUrl;
    }

    if (
        options?.allowHttpLoopbackInTests &&
        parsedUrl.protocol === 'http:' &&
        LOOPBACK_HOSTNAMES.includes(parsedUrl.hostname) &&
        typeof process !== 'undefined' &&
        process.env.NODE_ENV === 'test'
    ) {
        return parsedUrl;
    }

    throwSignerError(SignerErrorCode.CONFIG_ERROR, {
        message: `${field} must use HTTPS`,
    });
}
