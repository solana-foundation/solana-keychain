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
