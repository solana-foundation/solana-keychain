import { afterEach, describe, expect, it } from 'vitest';

import { assertHttpsUrl } from '../url.js';

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

describe('assertHttpsUrl', () => {
    afterEach(() => {
        process.env.NODE_ENV = ORIGINAL_NODE_ENV;
    });

    it('returns the parsed URL for HTTPS endpoints', () => {
        const url = assertHttpsUrl('https://api.example.com/base', 'apiBaseUrl');
        expect(url.host).toBe('api.example.com');
        expect(url.protocol).toBe('https:');
    });

    it('throws CONFIG_ERROR for malformed URLs', () => {
        expect(() => assertHttpsUrl('not a url', 'apiBaseUrl')).toThrow('apiBaseUrl is not a valid URL');
    });

    it('throws CONFIG_ERROR for non-HTTPS URLs', () => {
        expect(() => assertHttpsUrl('http://api.example.com', 'apiBaseUrl')).toThrow('apiBaseUrl must use HTTPS');
    });

    it('names the offending config field in the error', () => {
        expect(() => assertHttpsUrl('http://api.example.com', 'vaultAddr')).toThrow('vaultAddr must use HTTPS');
    });

    describe('allowHttpLoopbackInTests', () => {
        it('allows HTTP loopback URLs when NODE_ENV=test', () => {
            process.env.NODE_ENV = 'test';
            for (const host of ['localhost', '127.0.0.1', '[::1]']) {
                const url = assertHttpsUrl(`http://${host}:8200`, 'vaultAddr', { allowHttpLoopbackInTests: true });
                expect(url.protocol).toBe('http:');
            }
        });

        it('rejects HTTP on non-loopback hosts even when NODE_ENV=test', () => {
            process.env.NODE_ENV = 'test';
            expect(() =>
                assertHttpsUrl('http://api.example.com', 'vaultAddr', { allowHttpLoopbackInTests: true }),
            ).toThrow('vaultAddr must use HTTPS');
        });

        it('rejects HTTP loopback outside NODE_ENV=test', () => {
            process.env.NODE_ENV = 'production';
            expect(() =>
                assertHttpsUrl('http://localhost:8200', 'vaultAddr', { allowHttpLoopbackInTests: true }),
            ).toThrow('vaultAddr must use HTTPS');
        });
    });
});
