import { afterEach, describe, expect, it, vi } from 'vitest';

import { SignerError, SignerErrorCode } from '../errors.js';
import { fetchSignerJson } from '../http.js';

function mockFetch(impl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(impl as typeof fetch);
    return spy;
}

async function expectSignerError(promise: Promise<unknown>, code: SignerErrorCode): Promise<SignerError> {
    try {
        await promise;
    } catch (error) {
        expect(error).toBeInstanceOf(SignerError);
        expect((error as SignerError).code).toBe(code);
        return error as SignerError;
    }
    throw new Error('expected promise to reject');
}

describe('fetchSignerJson', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('returns the parsed JSON payload on success', async () => {
        mockFetch(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));

        const result = await fetchSignerJson<{ ok: boolean }>({
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        expect(result).toEqual({ ok: true });
    });

    it('passes through method, headers and body and rejects redirects', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));

        await fetchSignerJson({
            init: { body: '{"a":1}', headers: { Authorization: 'Bearer t' }, method: 'POST' },
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        const [, init] = spy.mock.calls[0];
        expect(init?.method).toBe('POST');
        expect(init?.body).toBe('{"a":1}');
        expect(init?.redirect).toBe('error');
        expect(init?.signal).toBeInstanceOf(AbortSignal);
    });

    it('rejects redirects even when init.redirect is provided', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));

        await fetchSignerJson({
            init: { redirect: 'follow' },
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        const [, init] = spy.mock.calls[0];
        expect(init?.redirect).toBe('error');
    });

    it('prefers a caller-provided AbortSignal over the default timeout', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));
        const controller = new AbortController();

        await fetchSignerJson({
            init: { signal: controller.signal },
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        const [, init] = spy.mock.calls[0];
        expect(init?.signal).toBe(controller.signal);
    });

    it('throws HTTP_ERROR when fetch rejects', async () => {
        mockFetch(async () => {
            throw new TypeError('network down');
        });

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.HTTP_ERROR,
        );
        expect(error.message).toBe('Test network request failed');
        expect(error.context?.url).toBe('https://api.example.com');
    });

    it('throws REMOTE_API_ERROR with sanitized body on non-2xx status', async () => {
        mockFetch(async () => new Response('boom\u0000\n\nbad', { status: 502 }));

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.REMOTE_API_ERROR,
        );
        expect(error.message).toBe('Test API error: 502');
        expect(error.context?.status).toBe(502);
        expect(error.context?.response).toBe('boom bad');
    });

    it('throws PARSING_ERROR on invalid JSON', async () => {
        mockFetch(async () => new Response('not json', { status: 200 }));

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.PARSING_ERROR,
        );
        expect(error.message).toBe('Failed to parse Test response');
    });
});
