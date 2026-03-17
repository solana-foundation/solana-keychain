import { describe, expect, it } from 'vitest';

import {
    isSignerError,
    SignerError,
    SignerErrorCode,
    sanitizeRemoteErrorResponse,
    throwSignerError,
} from '../errors.js';

describe('sanitizeRemoteErrorResponse', () => {
    it('removes control characters and collapses whitespace', () => {
        const input = 'token=abc123\n\n\tserver\u0000error\r\n';
        const sanitized = sanitizeRemoteErrorResponse(input);

        expect(sanitized).toBe('token=abc123 server error');
    });

    it('truncates long responses and appends a marker', () => {
        const input = `prefix-${'a'.repeat(400)}`;
        const sanitized = sanitizeRemoteErrorResponse(input, 64);

        expect(sanitized.startsWith('prefix-')).toBe(true);
        expect(sanitized.endsWith('[truncated]')).toBe(true);
        expect(sanitized.length).toBeGreaterThan(64);
    });

    it('returns fallback for empty responses', () => {
        expect(sanitizeRemoteErrorResponse(' \n\t\r ')).toBe('[empty remote response]');
    });
});

describe('isSignerError', () => {
    it('returns true for matching code', () => {
        const error = new SignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: 'API error: 403',
            response: 'Forbidden',
            status: 403,
        });
        expect(isSignerError(error, SignerErrorCode.REMOTE_API_ERROR)).toBe(true);
    });

    it('returns false for non-matching code', () => {
        const error = new SignerError(SignerErrorCode.HTTP_ERROR, { message: 'fail' });
        expect(isSignerError(error, SignerErrorCode.REMOTE_API_ERROR)).toBe(false);
    });

    it('returns false for non-SignerError', () => {
        expect(isSignerError(new Error('oops'), SignerErrorCode.HTTP_ERROR)).toBe(false);
        expect(isSignerError(null, SignerErrorCode.HTTP_ERROR)).toBe(false);
    });

    it('provides typed context access after narrowing', () => {
        try {
            throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
                message: 'API error: 500',
                response: 'Internal Server Error',
                status: 500,
            });
        } catch (e) {
            if (isSignerError(e, SignerErrorCode.REMOTE_API_ERROR)) {
                // These accesses are type-safe after narrowing
                expect(e.context?.status).toBe(500);
                expect(e.context?.response).toBe('Internal Server Error');
            }
        }
    });
});
