import { afterEach, describe, expect, it, vi } from 'vitest';

import { SignerError, SignerErrorCode } from '../errors.js';
import { fetchSignerJson, MAX_RESPONSE_BYTES } from '../http.js';

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

    it('composes a caller abortSignal with the timeout', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));
        const controller = new AbortController();

        await fetchSignerJson({
            abortSignal: controller.signal,
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        const [, init] = spy.mock.calls[0];
        const signal = init?.signal as AbortSignal;
        expect(signal).not.toBe(controller.signal);
        expect(signal.aborted).toBe(false);
        controller.abort(new Error('caller cancelled'));
        expect(signal.aborted).toBe(true);
    });

    it('composes a caller abortSignal with init.signal instead of the timeout', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));
        const abortController = new AbortController();
        const initController = new AbortController();

        await fetchSignerJson({
            abortSignal: abortController.signal,
            init: { signal: initController.signal },
            providerName: 'Test',
            url: 'https://api.example.com/v1/thing',
        });

        const signal = spy.mock.calls[0][1]?.signal as AbortSignal;
        initController.abort(new Error('init cancelled'));
        expect(signal.aborted).toBe(true);
    });

    it('aborts the request when the timeout fires before the caller signal', async () => {
        vi.useFakeTimers();
        try {
            const spy = mockFetch(
                async (_input, init) =>
                    await new Promise<Response>((_resolve, reject) => {
                        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
                    }),
            );
            const controller = new AbortController();

            const promise = fetchSignerJson({
                abortSignal: controller.signal,
                providerName: 'Test',
                timeoutMs: 50,
                url: 'https://api.example.com',
            });
            const rejects = expectSignerError(promise, SignerErrorCode.HTTP_ERROR);

            await vi.advanceTimersByTimeAsync(50);
            await rejects;
            expect(spy).toHaveBeenCalledOnce();
            expect(controller.signal.aborted).toBe(false);
        } finally {
            vi.useRealTimers();
        }
    });

    it('makes no request and throws the abort reason for an already-aborted signal', async () => {
        const spy = mockFetch(async () => new Response('{}', { status: 200 }));
        const reason = new Error('already cancelled');

        await expect(
            fetchSignerJson({
                abortSignal: AbortSignal.abort(reason),
                providerName: 'Test',
                url: 'https://api.example.com',
            }),
        ).rejects.toBe(reason);
        expect(spy).not.toHaveBeenCalled();
    });

    it('throws the abort reason rather than HTTP_ERROR when the caller aborts mid-flight', async () => {
        const controller = new AbortController();
        const reason = new Error('caller cancelled');
        mockFetch(
            async (_input, init) =>
                await new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
                    controller.abort(reason);
                }),
        );

        await expect(
            fetchSignerJson({
                abortSignal: controller.signal,
                providerName: 'Test',
                url: 'https://api.example.com',
            }),
        ).rejects.toBe(reason);
    });

    it('throws the abort reason rather than PARSING_ERROR when the caller aborts during the body read', async () => {
        const controller = new AbortController();
        const reason = new Error('caller cancelled');
        mockFetch(
            async () =>
                ({
                    json: async () => {
                        controller.abort(reason);
                        throw new Error('aborted');
                    },
                    ok: true,
                    status: 200,
                }) as unknown as Response,
        );

        await expect(
            fetchSignerJson({
                abortSignal: controller.signal,
                providerName: 'Test',
                url: 'https://api.example.com',
            }),
        ).rejects.toBe(reason);
    });

    it('keeps the provider status on a non-2xx response even when the caller aborts during the body read', async () => {
        const controller = new AbortController();
        mockFetch(
            async () =>
                ({
                    ok: false,
                    status: 400,
                    text: async () => {
                        controller.abort(new Error('caller cancelled'));
                        throw new Error('aborted');
                    },
                }) as unknown as Response,
        );

        const error = await expectSignerError(
            fetchSignerJson({
                abortSignal: controller.signal,
                providerName: 'Test',
                url: 'https://api.example.com',
            }),
            SignerErrorCode.REMOTE_API_ERROR,
        );
        expect(error.context?.status).toBe(400);
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

    it('accepts a success body of exactly MAX_RESPONSE_BYTES', async () => {
        // `{"a":"…"}` framing is 9 bytes; pad the value so the body is exactly at the cap.
        const value = 'x'.repeat(MAX_RESPONSE_BYTES - 9);
        mockFetch(async () => new Response(`{"a":"${value}"}`, { status: 200 }));

        const result = await fetchSignerJson<{ a: string }>({
            providerName: 'Test',
            url: 'https://api.example.com',
        });

        expect(result.a).toBe(value);
    });

    it('throws PARSING_ERROR when a success body exceeds MAX_RESPONSE_BYTES', async () => {
        mockFetch(async () => new Response(`{"a":"${'x'.repeat(MAX_RESPONSE_BYTES)}"}`, { status: 200 }));

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.PARSING_ERROR,
        );
        expect(error.message).toBe('Test response exceeded maximum size');
        expect(error.context?.maxResponseBytes).toBe(MAX_RESPONSE_BYTES);
        expect(error.context?.status).toBe(200);
    });

    it('throws PARSING_ERROR when a non-2xx error body exceeds MAX_RESPONSE_BYTES', async () => {
        mockFetch(async () => new Response('x'.repeat(MAX_RESPONSE_BYTES + 1), { status: 502 }));

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.PARSING_ERROR,
        );
        expect(error.message).toBe('Test response exceeded maximum size');
        expect(error.context?.status).toBe(502);
    });

    it('fails fast on a Content-Length over the cap without reading the body', async () => {
        const read = vi.fn();
        mockFetch(
            async () =>
                ({
                    body: { getReader: () => ({ cancel: async () => {}, read }) },
                    headers: new Headers({ 'content-length': String(MAX_RESPONSE_BYTES + 1) }),
                    ok: true,
                    status: 200,
                }) as unknown as Response,
        );

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.PARSING_ERROR,
        );
        expect(error.message).toBe('Test response exceeded maximum size');
        expect(read).not.toHaveBeenCalled();
    });

    it('enforces the streaming cap even when Content-Length understates the body', async () => {
        const chunk = new TextEncoder().encode('x'.repeat(64 * 1024));
        let sent = 0;
        mockFetch(
            async () =>
                ({
                    body: {
                        getReader: () => ({
                            cancel: async () => {},
                            read: async () => {
                                sent += chunk.byteLength;
                                return { done: false, value: chunk };
                            },
                        }),
                    },
                    headers: new Headers({ 'content-length': '2' }),
                    ok: true,
                    status: 200,
                }) as unknown as Response,
        );

        const error = await expectSignerError(
            fetchSignerJson({ providerName: 'Test', url: 'https://api.example.com' }),
            SignerErrorCode.PARSING_ERROR,
        );
        expect(error.message).toBe('Test response exceeded maximum size');
        expect(sent).toBeLessThanOrEqual(MAX_RESPONSE_BYTES + chunk.byteLength);
    });

    it('falls back to response.json() when the response exposes no body stream', async () => {
        mockFetch(
            async () =>
                ({
                    body: null,
                    json: async () => ({ ok: true }),
                    ok: true,
                    status: 200,
                }) as unknown as Response,
        );

        const result = await fetchSignerJson<{ ok: boolean }>({
            providerName: 'Test',
            url: 'https://api.example.com',
        });

        expect(result).toEqual({ ok: true });
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
