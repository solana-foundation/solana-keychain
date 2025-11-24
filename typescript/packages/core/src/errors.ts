/**
 * Custom error codes for solana-keychain, specific to this library
 */
export enum SignerErrorCode {
    INVALID_PRIVATE_KEY = 'SIGNER_INVALID_PRIVATE_KEY',
    INVALID_PUBLIC_KEY = 'SIGNER_INVALID_PUBLIC_KEY',
    SIGNING_FAILED = 'SIGNER_SIGNING_FAILED',
    REMOTE_API_ERROR = 'SIGNER_REMOTE_API_ERROR',
    HTTP_ERROR = 'SIGNER_HTTP_ERROR',
    SERIALIZATION_ERROR = 'SIGNER_SERIALIZATION_ERROR',
    PARSING_ERROR = 'SIGNER_PARSING_ERROR',
    CONFIG_ERROR = 'SIGNER_CONFIG_ERROR',
    NOT_AVAILABLE = 'SIGNER_NOT_AVAILABLE',
    IO_ERROR = 'SIGNER_IO_ERROR',
    SIGNER_NOT_INITIALIZED = 'SIGNER_NOT_INITIALIZED',
    EXPECTED_SOLANA_SIGNER = 'SIGNER_EXPECTED_SOLANA_SIGNER',
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
