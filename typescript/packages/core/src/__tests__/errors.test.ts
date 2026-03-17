import { describe, expect, it } from 'vitest';

import { sanitizeRemoteErrorResponse } from '../errors.js';

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
