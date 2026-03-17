import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SignerErrorCode } from '../errors.js';
import { fetchWithSignerErrors } from '../http.js';

const mockFetch = vi.fn<typeof globalThis.fetch>();

beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch);
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('fetchWithSignerErrors', () => {
    it('returns parsed JSON on success', async () => {
        mockFetch.mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));

        const result = await fetchWithSignerErrors<{ ok: boolean }>('https://api.example.com', {}, 'Test');

        expect(result).toEqual({ ok: true });
    });

    it('passes options through to fetch', async () => {
        mockFetch.mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));

        await fetchWithSignerErrors('https://api.example.com/sign', { method: 'POST', body: '{}' }, 'Test');

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com/sign', { method: 'POST', body: '{}' });
    });

    it('throws HTTP_ERROR on network failure', async () => {
        mockFetch.mockRejectedValue(new TypeError('fetch failed'));

        await expect(fetchWithSignerErrors('https://api.example.com', {}, 'MyService')).rejects.toMatchObject({
            code: SignerErrorCode.HTTP_ERROR,
            message: 'MyService network request failed',
        });
    });

    it('throws REMOTE_API_ERROR on non-2xx response', async () => {
        mockFetch.mockResolvedValue(new Response('{"error":"Forbidden"}', { status: 403 }));

        await expect(fetchWithSignerErrors('https://api.example.com', {}, 'MyService')).rejects.toMatchObject({
            code: SignerErrorCode.REMOTE_API_ERROR,
            message: 'MyService API error: 403',
        });
    });

    it('sanitizes error response text', async () => {
        mockFetch.mockResolvedValue(new Response('a'.repeat(500), { status: 500 }));

        await expect(fetchWithSignerErrors('https://api.example.com', {}, 'Test')).rejects.toMatchObject({
            code: SignerErrorCode.REMOTE_API_ERROR,
            context: expect.objectContaining({
                response: expect.stringContaining('[truncated]'),
            }),
        });
    });

    it('handles unreadable error response body', async () => {
        const badResponse = new Response(null, { status: 502 });
        // Force .text() to reject
        vi.spyOn(badResponse, 'text').mockRejectedValue(new Error('body stream error'));
        mockFetch.mockResolvedValue(badResponse);

        await expect(fetchWithSignerErrors('https://api.example.com', {}, 'Test')).rejects.toMatchObject({
            code: SignerErrorCode.REMOTE_API_ERROR,
            context: expect.objectContaining({
                response: expect.stringContaining('Failed to read error response'),
            }),
        });
    });

    it('throws PARSING_ERROR when response is not valid JSON', async () => {
        mockFetch.mockResolvedValue(new Response('not json', { status: 200 }));

        await expect(fetchWithSignerErrors('https://api.example.com', {}, 'MyService')).rejects.toMatchObject({
            code: SignerErrorCode.PARSING_ERROR,
            message: 'Failed to parse MyService response',
        });
    });
});
