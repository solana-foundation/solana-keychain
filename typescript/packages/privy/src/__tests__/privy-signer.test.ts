import { generateKeyPair, signBytes } from '@solana/keys';
import { createSignableMessage, createSignerFromKeyPair, generateKeyPairSigner } from '@solana/signers';
import {
    Base64EncodedWireTransaction,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';
import { assertIsSolanaSigner } from '@solana/keychain-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PrivySigner } from '../privy-signer.js';
import { formatPrivyAuthorizationSignaturePayload, generatePrivyAuthorizationSignatures } from '../authorization.js';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        assertSignatureValid: vi.fn(),
        sanitizeRemoteErrorResponse:
            mod.sanitizeRemoteErrorResponse ??
            ((text: string) =>
                `${text
                    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim()
                    .slice(0, 256)} [truncated]`),
    };
});

global.fetch = vi.fn();

const MOCK_B64_WIRE_TX =
    'Af1fCRSrZ9ASprap8D3ZLPsbzeCs6uihvj/jfjm3UrAY72by5zKMRd7YAIbJCl9gyRHQbw+xdklET2ZNmZi3iA2AAQABAurnRuGN5bfL2osZZMdGlvL1qz8k0GbdLhiP1fICgkmsBUpTWpkpIQZNJOhxYNo4fHw1td28kruB5B+oQEEFRI1NhzEgE0w/YfwaeZi2Ns/mLoZvq2Sx5NVQg7Am7wrjGwEBAAxIZWxsbywgUHJpdnkA' as Base64EncodedWireTransaction;

vi.mock('@solana/transactions', async () => {
    const actual = await vi.importActual<typeof import('@solana/transactions')>('@solana/transactions');
    return {
        ...actual,
        getBase64EncodedWireTransaction: vi.fn(() => MOCK_B64_WIRE_TX),
    };
});

const createMockTransaction = (): Transaction & TransactionWithinSizeLimit & TransactionWithLifetime => {
    return {} as Transaction & TransactionWithinSizeLimit & TransactionWithLifetime;
};

describe('PrivySigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    const mockConfig = {
        apiBaseUrl: 'https://api.privy.test',
        appId: 'test-app-id',
        appSecret: 'test-app-secret',
        walletId: 'test-wallet-id',
    };

    const setupMockWalletResponse = (address: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    address,
                    chain_type: 'solana',
                    id: mockConfig.walletId,
                }),
            ok: true,
            status: 200,
        });
    };

    const setupMockSignMessageResponse = (signatureBase64: string) => {
        (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
            json: () =>
                Promise.resolve({
                    data: {
                        encoding: 'base64',
                        signature: signatureBase64,
                    },
                    method: 'signMessage',
                }),
            ok: true,
            status: 200,
        });
    };

    describe('create', () => {
        it('creates and initializes a PrivySigner', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            expect(signer.address).toBeTruthy();
            expect(signer.signMessages).toBeDefined();
            expect(signer.signTransactions).toBeDefined();
            expect(signer.isAvailable).toBeDefined();
            expect(typeof signer.address).toBe('string');
            assertIsSolanaSigner(signer);
        });

        it('sets address field correctly from API response', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            expect(signer.address).toBe(keyPair.address);
        });

        it('URL-encodes walletId in the request path and disables redirect following', async () => {
            const keyPair = await generateKeyPairSigner();
            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.resolve({ address: keyPair.address, chain_type: 'solana', id: '../../evil' }),
                ok: true,
                status: 200,
            });

            await PrivySigner.create({ ...mockConfig, walletId: '../../evil' });

            const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
            expect(url).toBe('https://api.privy.test/wallets/..%2F..%2Fevil');
            expect(init.redirect).toBe('error');
        });

        it('throws error on API failure', async () => {
            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 401,
                text: () => Promise.resolve('Unauthorized'),
            });

            await expect(PrivySigner.create(mockConfig)).rejects.toThrow();
        });

        it('throws error on invalid public key', async () => {
            setupMockWalletResponse('not-a-valid-address');

            await expect(PrivySigner.create(mockConfig)).rejects.toThrow();
        });

        describe('config validation', () => {
            it('throws CONFIG_ERROR when appId is missing', async () => {
                const invalidConfig = { ...mockConfig, appId: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when appSecret is missing', async () => {
                const invalidConfig = { ...mockConfig, appSecret: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when walletId is missing', async () => {
                const invalidConfig = { ...mockConfig, walletId: '' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('Missing required configuration fields'),
                });
            });

            it('throws CONFIG_ERROR when apiBaseUrl is not a valid URL', async () => {
                const invalidConfig = { ...mockConfig, apiBaseUrl: 'not-a-url' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('apiBaseUrl is not a valid URL'),
                });
            });

            it('throws CONFIG_ERROR when apiBaseUrl does not use HTTPS', async () => {
                const invalidConfig = { ...mockConfig, apiBaseUrl: 'http://api.privy.test' };
                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('apiBaseUrl must use HTTPS'),
                });
            });

            it('throws CONFIG_ERROR when authorizationRequestExpiryMs is negative', async () => {
                const invalidConfig = {
                    ...mockConfig,
                    authorizationContext: { sign_fns: [() => 'signature'] },
                    authorizationRequestExpiryMs: -1,
                };

                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('authorizationRequestExpiryMs must not be negative'),
                });
                expect(global.fetch).not.toHaveBeenCalled();
            });

            it('throws CONFIG_ERROR when requestDelayMs is negative', async () => {
                const invalidConfig = {
                    ...mockConfig,
                    requestDelayMs: -1,
                };

                await expect(PrivySigner.create(invalidConfig)).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                    message: expect.stringContaining('requestDelayMs must not be negative'),
                });
                expect(global.fetch).not.toHaveBeenCalled();
            });
        });

        describe('network errors', () => {
            it('throws HTTP_ERROR when fetch fails during create', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_HTTP_ERROR',
                    message: expect.stringContaining('Privy network request failed'),
                });
            });
        });

        describe('parsing errors', () => {
            it('throws PARSING_ERROR when response is invalid JSON', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                    json: () => Promise.reject(new Error('Invalid JSON')),
                    ok: true,
                    status: 200,
                });

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_PARSING_ERROR',
                    message: expect.stringContaining('Failed to parse Privy response'),
                });
            });
        });

        describe('response validation', () => {
            it('throws REMOTE_API_ERROR when address is missing from response', async () => {
                (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                    json: () =>
                        Promise.resolve({
                            chain_type: 'solana',
                            id: mockConfig.walletId,
                            // missing address field
                        }),
                    ok: true,
                    status: 200,
                });

                await expect(PrivySigner.create(mockConfig)).rejects.toMatchObject({
                    code: 'SIGNER_REMOTE_API_ERROR',
                    message: expect.stringContaining('Missing address in Privy wallet response'),
                });
            });
        });
    });

    describe('signMessages', () => {
        it('signs a message via Privy API', async () => {
            const keyPair = await generateKeyPair();
            const keyPairSigner = await createSignerFromKeyPair(keyPair);
            const address = keyPairSigner.address;

            setupMockWalletResponse(address);

            const signer = await PrivySigner.create(mockConfig);

            const messageContent = new Uint8Array([1, 2, 3, 4]);
            const signature = await signBytes(keyPair.privateKey, messageContent);

            const signatureBase64 = Buffer.from(signature).toString('base64');
            setupMockSignMessageResponse(signatureBase64);

            const message = createSignableMessage(messageContent);
            const [sigDict] = await signer.signMessages([message]);
            expect(sigDict).toBeTruthy();
            expect(sigDict?.[signer.address]).toBeTruthy();
        });

        it('injects Privy authorization context headers into signMessage requests', async () => {
            vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
            const keyPair = await generateKeyPair();
            const keyPairSigner = await createSignerFromKeyPair(keyPair);
            const address = keyPairSigner.address;
            const signFn = vi.fn((payload: Uint8Array) => {
                void payload;
                return 'authorization-signature';
            });

            setupMockWalletResponse(address);

            const signer = await PrivySigner.create({
                ...mockConfig,
                authorizationContext: { sign_fns: [signFn] },
            });

            const messageContent = new Uint8Array([1, 2, 3, 4]);
            const signature = await signBytes(keyPair.privateKey, messageContent);
            setupMockSignMessageResponse(Buffer.from(signature).toString('base64'));

            const message = createSignableMessage(messageContent);
            await signer.signMessages([message]);

            const payload = new TextDecoder().decode(signFn.mock.calls[0]?.[0]);
            expect(payload).toBe(
                '{"body":{"chain_type":"solana","method":"signMessage","params":{"encoding":"base64","message":"AQIDBA=="}},"headers":{"privy-app-id":"test-app-id","privy-request-expiry":"1900000"},"method":"POST","url":"https://api.privy.test/wallets/test-wallet-id/rpc","version":1}',
            );

            const fetchCalls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [
                string,
                RequestInit,
            ][];
            const lastFetchCall = fetchCalls[fetchCalls.length - 1];
            expect(lastFetchCall?.[0]).toBe('https://api.privy.test/wallets/test-wallet-id/rpc');
            expect(lastFetchCall?.[1]).toMatchObject({
                body: JSON.stringify({
                    chain_type: 'solana',
                    method: 'signMessage',
                    params: {
                        encoding: 'base64',
                        message: 'AQIDBA==',
                    },
                }),
                headers: {
                    'privy-authorization-signature': 'authorization-signature',
                    'privy-request-expiry': '1900000',
                },
                method: 'POST',
                redirect: 'error',
            });
        });

        it('preserves null authorizationRequestExpiryMs as a no-expiry authorization request', async () => {
            const keyPair = await generateKeyPair();
            const keyPairSigner = await createSignerFromKeyPair(keyPair);
            const address = keyPairSigner.address;
            const signFn = vi.fn((payload: Uint8Array) => {
                void payload;
                return 'authorization-signature';
            });

            setupMockWalletResponse(address);

            const signer = await PrivySigner.create({
                ...mockConfig,
                authorizationContext: { sign_fns: [signFn] },
                authorizationRequestExpiryMs: null,
            });

            const messageContent = new Uint8Array([1, 2, 3, 4]);
            const signature = await signBytes(keyPair.privateKey, messageContent);
            setupMockSignMessageResponse(Buffer.from(signature).toString('base64'));

            const message = createSignableMessage(messageContent);
            await signer.signMessages([message]);

            const payload = new TextDecoder().decode(signFn.mock.calls[0]?.[0]);
            expect(payload).toBe(
                '{"body":{"chain_type":"solana","method":"signMessage","params":{"encoding":"base64","message":"AQIDBA=="}},"headers":{"privy-app-id":"test-app-id"},"method":"POST","url":"https://api.privy.test/wallets/test-wallet-id/rpc","version":1}',
            );

            const fetchCalls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [
                string,
                RequestInit,
            ][];
            const lastFetchCall = fetchCalls[fetchCalls.length - 1];
            expect(lastFetchCall?.[1]).toMatchObject({
                headers: {
                    'privy-authorization-signature': 'authorization-signature',
                },
            });
            expect(lastFetchCall?.[1]?.headers).not.toHaveProperty('privy-request-expiry');
        });

        it('formats empty authorization request bodies like the Privy SDK', () => {
            const payload = formatPrivyAuthorizationSignaturePayload({
                body: {},
                headers: {
                    'privy-app-id': 'test-app-id',
                },
                method: 'POST',
                url: 'https://api.privy.test/v1/wallets',
                version: 1,
            });

            expect(new TextDecoder().decode(payload)).toBe(
                '{"body":"","headers":{"privy-app-id":"test-app-id"},"method":"POST","url":"https://api.privy.test/v1/wallets","version":1}',
            );
        });

        it('throws SERIALIZATION_ERROR for non-serializable array items', () => {
            try {
                formatPrivyAuthorizationSignaturePayload({
                    body: {
                        items: [Number.POSITIVE_INFINITY],
                    },
                    headers: {
                        'privy-app-id': 'test-app-id',
                    },
                    method: 'POST',
                    url: 'https://api.privy.test/v1/wallets',
                    version: 1,
                });
                throw new Error('Expected serialization to fail');
            } catch (error) {
                expect(error).toMatchObject({
                    code: 'SIGNER_SERIALIZATION_ERROR',
                    message: expect.stringContaining('Failed to serialize Privy authorization request'),
                });
            }
        });

        it('generates base64 DER authorization signatures from Privy private keys', async () => {
            const nodeCrypto = await import('node:crypto');
            const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', {
                namedCurve: 'prime256v1',
            });
            const privateKeyDer = privateKey.export({
                format: 'der',
                type: 'pkcs8',
            });
            const request = {
                body: {
                    chain_type: 'solana',
                    method: 'signMessage',
                    params: {
                        encoding: 'base64',
                        message: 'AQIDBA==',
                    },
                },
                headers: {
                    'privy-app-id': 'test-app-id',
                    'privy-request-expiry': '1900000',
                },
                method: 'POST' as const,
                url: 'https://api.privy.test/wallets/test-wallet-id/rpc',
                version: 1 as const,
            };
            const [signature] = await generatePrivyAuthorizationSignatures(request, {
                authorization_private_keys: [`wallet-auth:${Buffer.from(privateKeyDer).toString('base64')}`],
            });

            expect(signature).toBeTruthy();
            expect(
                nodeCrypto.verify(
                    'sha256',
                    formatPrivyAuthorizationSignaturePayload(request),
                    publicKey,
                    Buffer.from(signature ?? '', 'base64'),
                ),
            ).toBe(true);
        });

        it('generates authorization signatures from prefixed PEM private keys', async () => {
            const nodeCrypto = await import('node:crypto');
            const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', {
                namedCurve: 'prime256v1',
            });
            const privateKeyPem = privateKey.export({
                format: 'pem',
                type: 'pkcs8',
            });
            const request = {
                body: {
                    chain_type: 'solana',
                    method: 'signMessage',
                    params: {
                        encoding: 'base64',
                        message: 'AQIDBA==',
                    },
                },
                headers: {
                    'privy-app-id': 'test-app-id',
                    'privy-request-expiry': '1900000',
                },
                method: 'POST' as const,
                url: 'https://api.privy.test/wallets/test-wallet-id/rpc',
                version: 1 as const,
            };
            const [signature] = await generatePrivyAuthorizationSignatures(request, {
                authorization_private_keys: [`wallet-api:${privateKeyPem}`],
            });

            expect(signature).toBeTruthy();
            expect(
                nodeCrypto.verify(
                    'sha256',
                    formatPrivyAuthorizationSignaturePayload(request),
                    publicKey,
                    Buffer.from(signature ?? '', 'base64'),
                ),
            ).toBe(true);
        });

        it('throws HTTP_ERROR when fetch fails during signing', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Privy network request failed'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Privy signing response'),
            });
        });

        it('throws REMOTE_API_ERROR when signature is missing from response', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        data: {
                            encoding: 'base64',
                            // missing signature field
                        },
                        method: 'signMessage',
                    }),
                ok: true,
                status: 200,
            });

            const message = createSignableMessage(new Uint8Array([1, 2, 3, 4]));
            await expect(signer.signMessages([message])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signature in Privy response'),
            });
        });
    });

    describe('signTransactions', () => {
        it('handles API errors during transaction signing', async () => {
            const keyPair = await generateKeyPairSigner();

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve('Internal server error'),
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        it('injects Privy authorization context headers into signTransaction requests', async () => {
            vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
            const keyPair = await generateKeyPairSigner();
            const signFn = vi.fn((payload: Uint8Array) => {
                void payload;
                return 'transaction-authorization-signature';
            });

            setupMockWalletResponse(keyPair.address);

            const signer = await PrivySigner.create({
                ...mockConfig,
                authorizationContext: { sign_fns: [signFn] },
            });

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve('Internal server error'),
            });

            await expect(signer.signTransactions([createMockTransaction()])).rejects.toThrow();

            const payload = new TextDecoder().decode(signFn.mock.calls[0]?.[0]);
            expect(payload).toBe(
                `{"body":{"chain_type":"solana","method":"signTransaction","params":{"encoding":"base64","transaction":"${MOCK_B64_WIRE_TX}"}},"headers":{"privy-app-id":"test-app-id","privy-request-expiry":"1900000"},"method":"POST","url":"https://api.privy.test/wallets/test-wallet-id/rpc","version":1}`,
            );

            const fetchCalls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls as unknown as [
                string,
                RequestInit,
            ][];
            const lastFetchCall = fetchCalls[fetchCalls.length - 1];
            expect(lastFetchCall?.[1]).toMatchObject({
                body: JSON.stringify({
                    chain_type: 'solana',
                    method: 'signTransaction',
                    params: {
                        encoding: 'base64',
                        transaction: MOCK_B64_WIRE_TX,
                    },
                }),
                headers: {
                    'privy-authorization-signature': 'transaction-authorization-signature',
                    'privy-request-expiry': '1900000',
                },
                method: 'POST',
            });
        });

        it('sanitizes remote API error text in error context', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve(`topsecret\n\n${'x'.repeat(600)}\u0000`),
            });

            const mockTx = createMockTransaction();

            try {
                await signer.signTransactions([mockTx]);
                throw new Error('Expected signTransactions to throw');
            } catch (error) {
                if (!error || typeof error !== 'object' || !('code' in error) || !('context' in error)) {
                    throw error;
                }

                const signerError = error as { code: string; context?: { response?: string } };
                expect(signerError.code).toBe('SIGNER_REMOTE_API_ERROR');
                expect(signerError.context?.response).toContain('[truncated]');
                expect(signerError.context?.response).not.toContain('\n');
                expect(signerError.context?.response).not.toContain('\u0000');
            }
        });

        it('throws HTTP_ERROR when fetch fails during transaction signing', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network timeout'));

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
                message: expect.stringContaining('Privy network request failed'),
            });
        });

        it('throws PARSING_ERROR when response is invalid JSON', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () => Promise.reject(new Error('Invalid JSON')),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
                message: expect.stringContaining('Failed to parse Privy signing response'),
            });
        });

        it('throws REMOTE_API_ERROR when signed_transaction is missing from response', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);

            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                json: () =>
                    Promise.resolve({
                        data: {
                            encoding: 'base64',
                            // missing signed_transaction field
                        },
                        method: 'signTransaction',
                    }),
                ok: true,
                status: 200,
            });

            const mockTx = createMockTransaction();

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
                message: expect.stringContaining('Missing signed_transaction in Privy response'),
            });
        });
    });

    describe('isAvailable', () => {
        it('returns true when API is reachable', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);
            setupMockWalletResponse(keyPair.address);
            const available = await signer.isAvailable();
            expect(available).toBe(true);
        });

        it('returns false when API is unreachable', async () => {
            const keyPair = await generateKeyPairSigner();
            setupMockWalletResponse(keyPair.address);
            const signer = await PrivySigner.create(mockConfig);
            (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
                ok: false,
                status: 500,
                text: () => Promise.resolve('Server error'),
            });
            const available = await signer.isAvailable();
            expect(available).toBe(false);
        });
    });
});
