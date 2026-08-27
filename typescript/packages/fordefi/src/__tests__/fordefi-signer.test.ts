import { createHash, generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    assertIsSolanaTransactionSigner,
    assertSignatureValid,
    isSolanaMessageSigner,
    isSolanaModifyingSigner,
    isSolanaSendingSigner,
    isSolanaSigner,
    isSolanaTransactionSigner,
    type SignerError,
} from '@solana/keychain-core';
import { createCosignedWireTransaction, createSignedWireTransaction } from '@solana/keychain-test-utils';
import { isTransactionModifyingSigner, isTransactionPartialSigner, isTransactionSendingSigner } from '@solana/signers';

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

import { createFordefiSigner, type FordefiSignerConfig } from '../fordefi-signer.js';
import type { SolanaChainUniqueId } from '../types.js';

global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';

const { privateKey: testPrivateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const TEST_PEM = testPrivateKey.export({ type: 'sec1', format: 'pem' }) as string;

const MOCK_SIGNATURE_BYTES = new Uint8Array(64).fill(0xab);
const MOCK_SIGNATURE_BASE64 = Buffer.from(MOCK_SIGNATURE_BYTES).toString('base64');

const mockConfig: FordefiSignerConfig & { chain?: undefined; pushMode?: undefined } = {
    accessToken: 'test-token',
    apiBaseUrl: 'https://api.test.fordefi.com',
    privateKeyPem: TEST_PEM,
    publicKey: MOCK_ADDRESS,
    vaultId: 'test-vault-id',
};

const nativeConfig = {
    ...mockConfig,
    chain: 'solana_mainnet',
} satisfies FordefiSignerConfig;

function mockCreateTxResponse(id = 'tx-123') {
    return new Response(JSON.stringify({ id }), { status: 200 });
}

function mockPollResponse(state: string, sigBase64?: string, rawTransaction?: string) {
    const body: Record<string, unknown> = { state };
    if (sigBase64) {
        body.signatures = [{ data: sigBase64 }];
    }
    if (rawTransaction) {
        body.raw_transaction = rawTransaction;
    }
    return new Response(JSON.stringify(body), { status: 200 });
}

// Native mode parses real wire bytes, and a v1 envelope cannot be faked by hand.
async function setupNativeBroadcast(version: 0 | 1) {
    const fixture = await createSignedWireTransaction(version);
    const config = {
        ...mockConfig,
        chain: 'solana_mainnet',
        publicKey: fixture.feePayer,
    } satisfies FordefiSignerConfig;
    return { config, fixture };
}

// Manual mode replaces the caller's transaction with real wire bytes, so the
// response has to be a decodable transaction the vault signed.
async function setupNativeManual(version: 0 | 1) {
    const fixture = await createSignedWireTransaction(version);
    const config = {
        ...mockConfig,
        chain: 'solana_mainnet',
        publicKey: fixture.feePayer,
        pushMode: 'manual',
    } satisfies FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode: 'manual' };
    return { config, fixture };
}

function unsignedManualTransaction(feePayer: string, messageBytes = new Uint8Array(32)) {
    return { messageBytes, signatures: { [feePayer]: null } } as never;
}

function idempotencyKeyOf(input: Uint8Array) {
    const digest = createHash('sha256').update(input).digest().subarray(0, 16);
    digest[6] = (digest[6]! & 0x0f) | 0x40;
    digest[8] = (digest[8]! & 0x3f) | 0x80;
    const hex = digest.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function mockVaultResponse(address: string = MOCK_ADDRESS) {
    return new Response(JSON.stringify({ address, id: 'test-vault-id' }), { status: 200 });
}

describe('createFordefiSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('basic construction', () => {
        it('should create a signer with valid config', async () => {
            const signer = await createFordefiSigner(mockConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        it('should satisfy the SolanaTransactionSigner and SolanaMessageSigner interfaces', async () => {
            const signer = await createFordefiSigner(mockConfig);
            expect(() => assertIsSolanaTransactionSigner(signer)).not.toThrow();
            expect(isSolanaMessageSigner(signer)).toBe(true);
        });

        it('should use the configured publicKey without a vault fetch', async () => {
            const signer = await createFordefiSigner(mockConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
            expect(fetch).not.toHaveBeenCalled();
        });

        it('should throw on empty accessToken', async () => {
            await expect(createFordefiSigner({ ...mockConfig, accessToken: '' })).rejects.toThrow();
        });

        it('should throw on empty vaultId', async () => {
            await expect(createFordefiSigner({ ...mockConfig, vaultId: '' })).rejects.toThrow();
        });

        it('should throw on empty publicKey', async () => {
            await expect(createFordefiSigner({ ...mockConfig, publicKey: '' })).rejects.toThrow();
        });

        it('should throw on HTTP apiBaseUrl', async () => {
            await expect(createFordefiSigner({ ...mockConfig, apiBaseUrl: 'http://insecure.com' })).rejects.toThrow();
        });

        it('should throw on invalid PEM', async () => {
            await expect(createFordefiSigner({ ...mockConfig, privateKeyPem: 'not-a-pem' })).rejects.toThrow();
        });

        it('should throw on invalid publicKey format', async () => {
            await expect(createFordefiSigner({ ...mockConfig, publicKey: 'not-a-pubkey' })).rejects.toThrow();
        });

        it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
            'should reject invalid maxPollAttempts %s before any network call',
            async maxPollAttempts => {
                await expect(createFordefiSigner({ ...mockConfig, maxPollAttempts })).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                });
                expect(fetch).not.toHaveBeenCalled();
            },
        );

        it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
            'should reject invalid pollIntervalMs %s before any network call',
            async pollIntervalMs => {
                await expect(createFordefiSigner({ ...mockConfig, pollIntervalMs })).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                });
                expect(fetch).not.toHaveBeenCalled();
            },
        );
    });

    describe('custom requestSigner', () => {
        const customConfig: FordefiSignerConfig & { chain?: undefined; pushMode?: undefined } = {
            accessToken: 'test-token',
            apiBaseUrl: 'https://api.test.fordefi.com',
            publicKey: MOCK_ADDRESS,
            requestSigner: { signRequest: () => 'custom-sig-value' },
            vaultId: 'test-vault-id',
        };

        it('should create a signer without privateKeyPem when requestSigner is provided', async () => {
            const signer = await createFordefiSigner(customConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        it('should set x-signature from the custom requestSigner output', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(customConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await signer.signTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-signature', 'custom-sig-value');
        });

        it('should support an async requestSigner', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner({
                ...customConfig,
                requestSigner: { signRequest: async () => 'async-sig-value' },
            });
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await signer.signTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-signature', 'async-sig-value');
        });

        it('should reject when neither privateKeyPem nor requestSigner is provided', async () => {
            await expect(createFordefiSigner({ ...customConfig, requestSigner: undefined })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });

        it('should reject when both privateKeyPem and requestSigner are provided', async () => {
            await expect(createFordefiSigner({ ...customConfig, privateKeyPem: TEST_PEM })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction via black box submit + poll', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            const results = await signer.signTransactions([mockTx]);
            expect(results).toHaveLength(1);
            expect(results[0]).toHaveProperty(MOCK_ADDRESS);

            expect(fetch).toHaveBeenCalledTimes(2);
            const call = vi.mocked(fetch).mock.calls[0]!;
            expect(call[0]).toBe('https://api.test.fordefi.com/api/v1/transactions');
            const postOpts = call[1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('black_box_signature');
            expect(body.details.format).toBe('hash_binary');
            expect(body.details).toHaveProperty('hash_binary');
            expect(postOpts.headers).toHaveProperty('Authorization', 'Bearer test-token');
            expect(postOpts.headers).toHaveProperty('x-signature');
            expect(postOpts.headers).toHaveProperty('x-timestamp');
            expect(postOpts.headers).not.toHaveProperty('x-idempotence-id');
        });

        it('should return the raw Fordefi signature directly without wire-tx round-trip', async () => {
            // Black box mode must NOT assemble a local wire tx and re-extract the
            // signature by position: that assumed Fordefi was signer #0 and broke
            // multi-signature / co-signed transactions. Instead the raw Ed25519
            // signature (valid regardless of account index) is returned directly.
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32).fill(0x11) } as never;

            const results = await signer.signTransactions([mockTx]);

            expect(results[0]).toHaveProperty(MOCK_ADDRESS);
            expect(Object.values(results[0]!)[0]).toEqual(MOCK_SIGNATURE_BYTES);
        });

        it('should handle failed transaction state', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('error_signing'));

            const signer = await createFordefiSigner(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        it('should timeout after max poll attempts', async () => {
            const signer = await createFordefiSigner({
                ...mockConfig,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
            });

            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValue(mockPollResponse('pending_signature'));

            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        it('should handle submit API error', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        // Black-box mode only signs, so a failed submit has no on-chain outcome to be unconfirmed about.
        it('does not report a 5xx on a black-box submit as unconfirmed', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ message: 'boom' }), { status: 502 }));

            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            const error = await signer.signTransactions([mockTx]).then(
                () => {
                    throw new Error('expected the submit failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );
            expect(error.code).toBe('SIGNER_REMOTE_API_ERROR');
        });

        it('should handle completed state without signatures', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed')); // no signatures

            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });
    });

    describe('signMessages', () => {
        it('should sign a message via black box submit + poll', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-1'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(mockConfig);
            const results = await signer.signMessages([{ content: new Uint8Array(32), signatures: {} }]);
            expect(results).toHaveLength(1);

            expect(fetch).toHaveBeenCalledTimes(2);
            const call = vi.mocked(fetch).mock.calls[0]!;
            expect(call[0]).toBe('https://api.test.fordefi.com/api/v1/transactions');
            const postOpts = call[1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('black_box_signature');
            expect(body.details.format).toBe('hash_binary');
            expect(body.details).toHaveProperty('hash_binary');
        });

        it('should sign multiple messages serially with delay', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-1'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64))
                .mockResolvedValueOnce(mockCreateTxResponse('msg-2'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner({ ...mockConfig, requestDelayMs: 1 });
            const results = await signer.signMessages([
                { content: new Uint8Array(32), signatures: {} },
                { content: new Uint8Array(32), signatures: {} },
            ]);
            expect(results).toHaveLength(2);
            expect(fetch).toHaveBeenCalledTimes(4);
        });

        it('should throw when completed state has no signatures', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-empty'))
                .mockResolvedValueOnce(mockPollResponse('completed'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on failed state', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-fail'))
                .mockResolvedValueOnce(mockPollResponse('aborted'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on submit API error', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on signature with wrong byte length', async () => {
            const signer = await createFordefiSigner(mockConfig);
            const shortSig = Buffer.from(new Uint8Array(32).fill(0xab)).toString('base64');
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-short'))
                .mockResolvedValueOnce(mockPollResponse('completed', shortSig));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });
    });

    describe('signAndSendTransactions (native solana mode)', () => {
        it.each([0, 1] as const)(
            'should expose a TransactionSendingSigner and return the broadcast signature from a v%i envelope',
            async version => {
                const { config, fixture } = await setupNativeBroadcast(version);
                vi.mocked(fetch)
                    .mockResolvedValueOnce(mockCreateTxResponse('tx-native'))
                    .mockResolvedValueOnce(
                        mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction),
                    );

                const signer = await createFordefiSigner(config);
                expect(
                    isTransactionSendingSigner(
                        signer as unknown as { [key: string]: unknown; address: typeof signer.address },
                    ),
                ).toBe(true);

                const mockTx = {
                    messageBytes: new Uint8Array(32),
                    signatures: { [fixture.feePayer]: null },
                } as never;
                const results = await signer.signAndSendTransactions([mockTx]);
                expect(results).toHaveLength(1);

                expect(results[0]).toStrictEqual(fixture.signature);
                expect(assertSignatureValid).toHaveBeenCalledWith(
                    expect.objectContaining({
                        data: fixture.messageBytes,
                        signerAddress: fixture.feePayer,
                    }),
                );

                const call = vi.mocked(fetch).mock.calls[0]!;
                const postOpts = call[1] as RequestInit;
                const body = JSON.parse(postOpts.body as string);
                expect(body.type).toBe('solana_transaction');
                expect(body.details.type).toBe('solana_serialized_transaction_message');
                expect(body.details.chain).toBe('solana_mainnet');
                expect(body.details.push_mode).toBe('auto');
                expect(body.details).toHaveProperty('data');
                expect(body.details).not.toHaveProperty('signatures');
            },
        );

        it('sends a deterministic x-idempotence-id on the native create', async () => {
            const messageBytes = new Uint8Array(32).fill(0xab);
            const digest = createHash('sha256').update(messageBytes).digest().subarray(0, 16);
            digest[6] = (digest[6]! & 0x0f) | 0x40;
            digest[8] = (digest[8]! & 0x3f) | 0x80;
            const hex = digest.toString('hex');
            const expectedId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;

            const { config, fixture } = await setupNativeBroadcast(1);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-native'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await createFordefiSigner(config);
            const mockTx = { messageBytes, signatures: { [fixture.feePayer]: null } } as never;
            await signer.signAndSendTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-idempotence-id', expectedId);
        });

        it('does not expose the partial-signer method in native mode', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            // Kit classifies by method presence: a present-but-throwing
            // signTransactions would make Kit partial-sign and fail at runtime.
            expect((signer as unknown as Record<string, unknown>).signTransactions).toBeUndefined();
            expect('signTransactions' in signer).toBe(false);
            expect(isTransactionPartialSigner(guardInput)).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(true);
            expect(isSolanaSigner(guardInput)).toBe(true);
            expect(isSolanaTransactionSigner(guardInput)).toBe(false);
            expect(isSolanaSendingSigner(guardInput)).toBe(true);
        });

        it('should reject native multi-signer auto-broadcast before submitting remote work', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: {
                    [MOCK_ADDRESS]: null,
                    '22222222222222222222222222222222': null,
                },
            } as never;

            await expect(signer.signAndSendTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('should not expose TransactionSendingSigner in black box mode', async () => {
            const signer = await createFordefiSigner(mockConfig);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            expect('signAndSendTransactions' in signer).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(false);
            expect(isTransactionPartialSigner(guardInput)).toBe(true);
            expect(isSolanaSigner(guardInput)).toBe(true);
            expect(isSolanaTransactionSigner(guardInput)).toBe(true);
            expect(isSolanaSendingSigner(guardInput)).toBe(false);
        });

        it('should poll through intermediate pushable states', async () => {
            const { config, fixture } = await setupNativeBroadcast(1);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-push'))
                .mockResolvedValueOnce(mockPollResponse('pushing'))
                .mockResolvedValueOnce(mockPollResponse('confirming'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await createFordefiSigner({ ...config, pollIntervalMs: 1 });
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [fixture.feePayer]: null },
            } as never;
            const results = await signer.signAndSendTransactions([mockTx]);
            expect(results).toHaveLength(1);
            expect(fetch).toHaveBeenCalledTimes(4);
        });

        it('rejects a returned transaction whose fee-payer slot is unsigned', async () => {
            // Fordefi rewrites what it broadcasts, so the returned fee payer need not
            // be the vault, and without its signature there is no broadcast id.
            const fixture = await createCosignedWireTransaction(1);
            const config = {
                ...mockConfig,
                chain: 'solana_mainnet',
                publicKey: fixture.cosigner,
            } satisfies FordefiSignerConfig;
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-unsigned-payer'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await createFordefiSigner(config);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [fixture.cosigner]: null },
            } as never;

            const error = await signer.signAndSendTransactions([mockTx]).then(
                () => {
                    throw new Error('expected the unsigned fee payer to be rejected');
                },
                (thrown: SignerError) => thrown,
            );
            expect(error.code).toBe('SIGNER_BROADCAST_UNCONFIRMED');

            // Our own error, not a raw kit SolanaError leaking through.
            const cause = error.context?.cause as SignerError;
            expect(cause.code).toBe('SIGNER_SIGNING_FAILED');
            expect(cause.context?.message).toContain('no fee-payer signature');
        });

        it('reports a 5xx on submit as unconfirmed with no transaction id', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ message: 'boom' }), { status: 502 }));

            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            const error = await signer.signAndSendTransactions([mockTx]).then(
                () => {
                    throw new Error('expected the submit failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );
            expect(error.code).toBe('SIGNER_BROADCAST_UNCONFIRMED');
            expect(error.context?.providerTransactionId).toBeUndefined();
            expect(error.context?.status).toBe(502);
        });

        it('reports an accepted submit with no id as unconfirmed', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ state: 'pending' }), { status: 200 }));

            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            const error = await signer.signAndSendTransactions([mockTx]).then(
                () => {
                    throw new Error('expected the submit failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );
            expect(error.code).toBe('SIGNER_BROADCAST_UNCONFIRMED');
            expect(error.context?.providerTransactionId).toBeUndefined();
            expect(error.context?.status).toBeUndefined();
        });

        it('keeps a 4xx on submit a plain failure', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            const error = await signer.signAndSendTransactions([mockTx]).then(
                () => {
                    throw new Error('expected the submit failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );
            expect(error.code).toBe('SIGNER_REMOTE_API_ERROR');
        });

        it('should throw when raw_transaction is missing from response', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-no-raw'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(nativeConfig);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            await expect(signer.signAndSendTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
                context: expect.objectContaining({ providerTransactionId: 'tx-no-raw' }) as object,
                message: expect.stringContaining('tx-no-raw') as string,
            });
        });

        it('should throw on failed state', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-fail'))
                .mockResolvedValueOnce(mockPollResponse('mined_reverted'));

            const signer = await createFordefiSigner(nativeConfig);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            await expect(signer.signAndSendTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_BROADCAST_UNCONFIRMED',
                context: expect.objectContaining({ providerTransactionId: 'tx-fail' }) as object,
            });
        });
    });

    describe('modifyAndSignTransactions (native manual mode)', () => {
        it.each([0, 1] as const)(
            'should replace the caller transaction with the one Fordefi signed from a v%i envelope',
            async version => {
                const { config, fixture } = await setupNativeManual(version);
                vi.mocked(fetch)
                    .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                    .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));

                const signer = await createFordefiSigner(config);
                const results = await signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer)]);

                expect(results).toHaveLength(1);
                // Continuing from the caller's own bytes would leave downstream
                // signers signing a message the Fordefi signature does not cover.
                expect(results[0]!.messageBytes).toStrictEqual(fixture.messageBytes);
                expect(results[0]!.signatures[fixture.feePayer]).toStrictEqual(fixture.signature);
                expect(results[0]!.lifetimeConstraint).toBeDefined();

                // The signature covers what Fordefi returned, not what was submitted.
                expect(assertSignatureValid).toHaveBeenCalledWith(
                    expect.objectContaining({
                        data: fixture.messageBytes,
                        signerAddress: fixture.feePayer,
                    }),
                );
            },
        );

        it('should submit solana_transaction with push_mode manual', async () => {
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));

            const signer = await createFordefiSigner(config);
            await signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer)]);

            const postOpts = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('solana_transaction');
            expect(body.details.type).toBe('solana_serialized_transaction_message');
            expect(body.details.push_mode).toBe('manual');
        });

        it('namespaces the x-idempotence-id so the same bytes cannot reuse an auto create', async () => {
            const messageBytes = new Uint8Array(32).fill(0xab);
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));

            const signer = await createFordefiSigner(config);
            await signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer, messageBytes)]);

            const namespace = Buffer.from(`fordefi:solana:manual:solana_mainnet:${config.vaultId}:`, 'utf8');
            const postOpts = vi.mocked(fetch).mock.calls[0]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty(
                'x-idempotence-id',
                idempotencyKeyOf(Buffer.concat([namespace, Buffer.from(messageBytes)])),
            );
            expect(postOpts.headers).not.toHaveProperty('x-idempotence-id', idempotencyKeyOf(messageBytes));
        });

        it('exposes only the modifying method, so Kit cannot route it as a partial or sending signer', async () => {
            const { config } = await setupNativeManual(0);
            const signer = await createFordefiSigner(config);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            expect('signTransactions' in signer).toBe(false);
            expect('signAndSendTransactions' in signer).toBe(false);
            expect(isTransactionModifyingSigner(guardInput)).toBe(true);
            expect(isTransactionPartialSigner(guardInput)).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(false);
            expect(isSolanaSigner(guardInput)).toBe(true);
            expect(isSolanaModifyingSigner(guardInput)).toBe(true);
            expect(isSolanaTransactionSigner(guardInput)).toBe(false);
            expect(isSolanaSendingSigner(guardInput)).toBe(false);
            expect(isSolanaMessageSigner(guardInput)).toBe(true);
        });

        it('rejects a transaction the vault does not pay for before submitting remote work', async () => {
            const { config, fixture } = await setupNativeManual(0);
            const signer = await createFordefiSigner(config);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { '22222222222222222222222222222222': null, [fixture.feePayer]: null },
            } as never;

            await expect(signer.modifyAndSignTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('rejects an already-signed transaction, whose signatures the rewrite would invalidate', async () => {
            const { config, fixture } = await setupNativeManual(0);
            const signer = await createFordefiSigner(config);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [fixture.feePayer]: MOCK_SIGNATURE_BYTES },
            } as never;

            await expect(signer.modifyAndSignTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('rejects a response without raw_transaction, having nothing to continue from', async () => {
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(config);
            await expect(
                signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer)]),
            ).rejects.toMatchObject({ code: 'SIGNER_SIGNING_FAILED' });
        });

        it('rejects a returned transaction that the configured vault did not sign', async () => {
            const fixture = await createCosignedWireTransaction(0);
            const config = {
                ...mockConfig,
                chain: 'solana_mainnet',
                publicKey: fixture.feePayer,
                pushMode: 'manual',
            } satisfies FordefiSignerConfig & { chain: SolanaChainUniqueId; pushMode: 'manual' };
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));

            const signer = await createFordefiSigner(config);
            await expect(
                signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer)]),
            ).rejects.toMatchObject({ code: 'SIGNER_SIGNING_FAILED' });
        });

        it('leaves the caller transaction untouched when the returned signature does not verify', async () => {
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));
            vi.mocked(assertSignatureValid).mockRejectedValueOnce(new Error('signature does not match'));

            const signer = await createFordefiSigner(config);
            const callerTransaction = unsignedManualTransaction(fixture.feePayer);
            const before = structuredClone(callerTransaction);

            await expect(signer.modifyAndSignTransactions([callerTransaction])).rejects.toThrow(
                'signature does not match',
            );
            expect(callerTransaction).toStrictEqual(before);
        });

        it('does not leak the access token or the request key into a failure', async () => {
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            const signer = await createFordefiSigner(config);
            const error = await signer.modifyAndSignTransactions([unsignedManualTransaction(fixture.feePayer)]).then(
                () => {
                    throw new Error('expected the submit failure to be reported');
                },
                (thrown: SignerError) => thrown,
            );

            const reported = `${error.message} ${JSON.stringify(error.context)} ${JSON.stringify(error)}`;
            expect(reported).not.toContain(config.accessToken);
            expect(reported).not.toContain(TEST_PEM);
        });

        it('keeps the caller lifetime when Fordefi did not refresh the blockhash', async () => {
            const { config, fixture } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', undefined, fixture.wireTransaction));

            // Fordefi does not report a lastValidBlockHeight, so a surviving
            // blockhash must not lose the caller's expiry height.
            const lifetimeConstraint = { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 100n };
            const signer = await createFordefiSigner(config);
            const results = await signer.modifyAndSignTransactions([
                {
                    lifetimeConstraint,
                    messageBytes: new Uint8Array(32),
                    signatures: { [fixture.feePayer]: null },
                } as never,
            ]);

            expect(results[0]!.lifetimeConstraint).toStrictEqual(lifetimeConstraint);
        });

        it('should reject pushMode manual without chain', async () => {
            await expect(
                createFordefiSigner({ ...mockConfig, pushMode: 'manual' } as FordefiSignerConfig),
            ).rejects.toMatchObject({ code: 'SIGNER_CONFIG_ERROR' });
        });

        it('should reject an unrecognized pushMode rather than defaulting it to auto', async () => {
            await expect(
                createFordefiSigner({
                    ...mockConfig,
                    chain: 'solana_mainnet',
                    pushMode: 'push',
                } as unknown as FordefiSignerConfig),
            ).rejects.toMatchObject({ code: 'SIGNER_CONFIG_ERROR' });
        });

        it('should still expose the sending method when pushMode is explicitly auto', async () => {
            const signer = await createFordefiSigner({ ...nativeConfig, pushMode: 'auto' });
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            expect(isTransactionSendingSigner(guardInput)).toBe(true);
            expect(isTransactionModifyingSigner(guardInput)).toBe(false);
        });
    });

    describe('failure states', () => {
        // Canonical Fordefi terminal failure states (must stay in parity with the Rust backend).
        const FAILURE_STATES = [
            'aborted',
            'cancelled',
            'completed_reverted',
            'dropped',
            'error_pushing_to_blockchain',
            'error_signing',
            'insufficient_funds',
            'mined_reverted',
        ];

        it.each(FAILURE_STATES)('should treat "%s" as a terminal failure', async state => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse(state));

            const signer = await createFordefiSigner(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });
    });

    describe('signMessages (native solana mode)', () => {
        it('should submit solana_message with personal_message_type', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-native'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64));

            const signer = await createFordefiSigner(nativeConfig);
            const results = await signer.signMessages([{ content: new Uint8Array(32), signatures: {} }]);
            expect(results).toHaveLength(1);

            const call = vi.mocked(fetch).mock.calls[0]!;
            const postOpts = call[1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('solana_message');
            expect(body.details.type).toBe('personal_message_type');
            expect(body.details.chain).toBe('solana_mainnet');
            expect(body.details).toHaveProperty('raw_data');
        });

        it('should throw when completed state has no signatures', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-empty'))
                .mockResolvedValueOnce(mockPollResponse('signed'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('should throw on aborted state', async () => {
            const signer = await createFordefiSigner(nativeConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-abort'))
                .mockResolvedValueOnce(mockPollResponse('aborted'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });
    });

    describe('isAvailable', () => {
        it('should return true when vault responds OK', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(mockVaultResponse());
            expect(await signer.isAvailable()).toBe(true);
        });

        it('should return false on API error', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 500 }));
            expect(await signer.isAvailable()).toBe(false);
        });

        it('should return false on network error', async () => {
            const signer = await createFordefiSigner(mockConfig);
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));
            expect(await signer.isAvailable()).toBe(false);
        });
    });
});
