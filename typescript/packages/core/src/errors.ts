/**
 * Custom error codes for solana-keychain, specific to this library
 */
export const SignerErrorCode = {
    CONFIG_ERROR: 'SIGNER_CONFIG_ERROR',
    EXPECTED_SOLANA_SIGNER: 'SIGNER_EXPECTED_SOLANA_SIGNER',
    HTTP_ERROR: 'SIGNER_HTTP_ERROR',
    INVALID_PRIVATE_KEY: 'SIGNER_INVALID_PRIVATE_KEY',
    INVALID_PUBLIC_KEY: 'SIGNER_INVALID_PUBLIC_KEY',
    IO_ERROR: 'SIGNER_IO_ERROR',
    NOT_AVAILABLE: 'SIGNER_NOT_AVAILABLE',
    PARSING_ERROR: 'SIGNER_PARSING_ERROR',
    REMOTE_API_ERROR: 'SIGNER_REMOTE_API_ERROR',
    SERIALIZATION_ERROR: 'SIGNER_SERIALIZATION_ERROR',
    SIGNER_NOT_INITIALIZED: 'SIGNER_NOT_INITIALIZED',
    SIGNING_FAILED: 'SIGNER_SIGNING_FAILED',
} as const;
export type SignerErrorCode = (typeof SignerErrorCode)[keyof typeof SignerErrorCode];

/**
 * Typed context fields per error code.
 *
 * When catching a `SignerError`, use `isSignerError(e, SignerErrorCode.REMOTE_API_ERROR)`
 * to narrow the `context` type and get typed access to code-specific fields.
 */
export type SignerErrorContextMap = {
    [SignerErrorCode.CONFIG_ERROR]: { cause?: unknown; message: string };
    [SignerErrorCode.EXPECTED_SOLANA_SIGNER]: { address?: string; message?: string };
    [SignerErrorCode.HTTP_ERROR]: { cause?: unknown; message: string; url?: string };
    [SignerErrorCode.INVALID_PRIVATE_KEY]: { cause?: unknown; message: string };
    [SignerErrorCode.INVALID_PUBLIC_KEY]: { cause?: unknown; message: string };
    [SignerErrorCode.IO_ERROR]: { cause?: unknown; message: string };
    [SignerErrorCode.NOT_AVAILABLE]: { cause?: unknown; message?: string };
    [SignerErrorCode.PARSING_ERROR]: { cause?: unknown; message: string };
    [SignerErrorCode.REMOTE_API_ERROR]: { message: string; response?: string; status?: number };
    [SignerErrorCode.SERIALIZATION_ERROR]: { cause?: unknown; message: string };
    [SignerErrorCode.SIGNER_NOT_INITIALIZED]: { message: string };
    [SignerErrorCode.SIGNING_FAILED]: { address?: string; cause?: unknown; message: string };
};

/** Context type for a given error code, with optional extra fields. */
export type SignerErrorContext<C extends SignerErrorCode = SignerErrorCode> = Record<string, unknown> &
    SignerErrorContextMap[C];

const DEFAULT_REMOTE_ERROR_RESPONSE_MAX_LENGTH = 256;

function isDisallowedAsciiControl(codePoint: number): boolean {
    return (
        codePoint <= 0x08 ||
        codePoint === 0x0b ||
        codePoint === 0x0c ||
        (codePoint >= 0x0e && codePoint <= 0x1f) ||
        codePoint === 0x7f
    );
}

function replaceDisallowedControlChars(input: string): string {
    let result = '';

    for (const char of input) {
        const codePoint = char.charCodeAt(0);
        result += isDisallowedAsciiControl(codePoint) ? ' ' : char;
    }

    return result;
}

/**
 * Custom error class for signer-specific errors.
 * Extends Error with code and context properties.
 *
 * Use `isSignerError()` to narrow the type and get typed `context` access.
 */
export class SignerError<C extends SignerErrorCode = SignerErrorCode> extends Error {
    readonly code: C;
    readonly context?: SignerErrorContext<C>;

    constructor(code: C, context?: SignerErrorContext<C>) {
        const message =
            context?.message && typeof context.message === 'string' ? context.message : `Signer error: ${code}`;
        super(message);
        this.name = 'SignerError';
        this.code = code;
        this.context = context;
    }
}

/**
 * Helper function to create signer-specific errors
 */
export function createSignerError<C extends SignerErrorCode>(code: C, context?: SignerErrorContext<C>): SignerError<C> {
    return new SignerError(code, context);
}

/**
 * Helper function to throw signer-specific errors
 */
export function throwSignerError<C extends SignerErrorCode>(code: C, context?: SignerErrorContext<C>): never {
    throw createSignerError(code, context);
}

/**
 * Type guard that narrows a caught error to a `SignerError` with a specific code.
 *
 * @example
 * ```typescript
 * try { await signer.signMessages([msg]); }
 * catch (e) {
 *   if (isSignerError(e, SignerErrorCode.REMOTE_API_ERROR)) {
 *     console.log(e.context?.status);   // number | undefined
 *     console.log(e.context?.response); // string | undefined
 *   }
 * }
 * ```
 */
export function isSignerError<C extends SignerErrorCode>(error: unknown, code: C): error is SignerError<C> {
    return error instanceof SignerError && error.code === code;
}

/**
 * Validate that a URL string is well-formed and uses HTTPS.
 *
 * @param url - The URL string to validate.
 * @param fieldName - Config field name for error messages (e.g. "apiBaseUrl", "vaultAddr").
 * @returns The parsed URL object.
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when the URL is invalid or does not use HTTPS.
 */
export function validateUrl(url: string, fieldName: string): URL {
    try {
        return new URL(url);
    } catch {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `${fieldName} is not a valid URL`,
        });
    }
}

export function validateHttpsUrl(url: string, fieldName: string): URL {
    const parsedUrl = validateUrl(url, fieldName);

    if (parsedUrl.protocol !== 'https:') {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `${fieldName} must use HTTPS`,
        });
    }

    return parsedUrl;
}

/**
 * Sanitize remote API error text before attaching it to error context/logs.
 * - Strips control characters.
 * - Collapses whitespace.
 * - Truncates long payloads.
 */
export function sanitizeRemoteErrorResponse(
    responseText: string,
    maxLength: number = DEFAULT_REMOTE_ERROR_RESPONSE_MAX_LENGTH,
): string {
    const normalized = replaceDisallowedControlChars(responseText).replace(/\s+/g, ' ').trim();

    if (!normalized) {
        return '[empty remote response]';
    }

    if (normalized.length <= maxLength) {
        return normalized;
    }

    return `${normalized.slice(0, maxLength)} [truncated]`;
}
