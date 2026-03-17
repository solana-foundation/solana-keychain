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
 * Custom error class for signer-specific errors
 * Extends Error with code and context properties
 */
export class SignerError extends Error {
    readonly code: SignerErrorCode;
    readonly context?: Record<string, unknown>;

    constructor(code: SignerErrorCode, context?: Record<string, unknown>) {
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
export function createSignerError(code: SignerErrorCode, context?: Record<string, unknown>): SignerError {
    return new SignerError(code, context);
}

/**
 * Helper function to throw signer-specific errors
 */
export function throwSignerError(code: SignerErrorCode, context?: Record<string, unknown>): never {
    throw createSignerError(code, context);
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
