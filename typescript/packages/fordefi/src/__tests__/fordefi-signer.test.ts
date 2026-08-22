import { createHash, generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

import {
    assertIsSolanaSigner,
    assertSignatureValid,
    isSolanaSendingSigner,
    isSolanaSigner,
    type SignerError,
    type SolanaSigner,
} from '@solana/keychain-core';
import { createCosignedWireTransaction, createSignedWireTransaction } from '@solana/keychain-test-utils';
import { isTransactionModifyingSigner, isTransactionPartialSigner, isTransactionSendingSigner } from '@solana/signers';
import type { Transaction, TransactionWithLifetime } from '@solana/transactions';

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

import {
    createFordefiSigner,
    type FordefiManualSignerConfig,
    type FordefiNativeManualSigner,
    type FordefiNativeSigner,
    FordefiSigner,
    type FordefiSignerConfig,
} from '../fordefi-signer.js';

// Mock fetch globally
global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';

// Generate a real P-256 key pair for tests
const { privateKey: testPrivateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const TEST_PEM = testPrivateKey.export({ type: 'sec1', format: 'pem' }) as string;

const MOCK_SIGNATURE_BYTES = new Uint8Array(64).fill(0xab);
const MOCK_SIGNATURE_BASE64 = Buffer.from(MOCK_SIGNATURE_BYTES).toString('base64');

const mockConfig: FordefiSignerConfig & { chain?: undefined } = {
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

const nativeManualConfig = {
    ...mockConfig,
    chain: 'solana_mainnet',
    pushMode: 'manual',
} satisfies FordefiManualSignerConfig;

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

async function setupNativeManual(version: 'legacy' | 0 | 1) {
    const versionedFixture = await createSignedWireTransaction(version === 'legacy' ? 0 : version);
    const fixture =
        version === 'legacy'
            ? (() => {
                  const wireBytes = Buffer.from(versionedFixture.wireTransaction, 'base64');
                  const messageOffset = 1 + wireBytes[0]! * 64;
                  if (wireBytes[messageOffset] !== 0x80) {
                      throw new Error('expected a v0 transaction fixture');
                  }
                  const legacyWireBytes = Buffer.concat([
                      wireBytes.subarray(0, messageOffset),
                      wireBytes.subarray(messageOffset + 1),
                  ]);
                  return {
                      ...versionedFixture,
                      messageBytes: new Uint8Array(legacyWireBytes.subarray(messageOffset)),
                      wireTransaction: legacyWireBytes.toString('base64'),
                  };
              })()
            : versionedFixture;
    const config = {
        ...mockConfig,
        chain: 'solana_mainnet',
        publicKey: fixture.feePayer,
        pushMode: 'manual',
    } satisfies FordefiManualSignerConfig;
    const transaction = {
        lifetimeConstraint: { blockhash: MOCK_ADDRESS, lastValidBlockHeight: 100n },
        messageBytes: fixture.messageBytes,
        signatures: { [fixture.feePayer]: null },
    } as unknown as Transaction & TransactionWithLifetime;
    return { config, fixture, transaction };
}

function replaceLegacyWireSignatures(wireTransaction: string, signatures: readonly (Uint8Array | null)[]): string {
    const bytes = Buffer.from(wireTransaction, 'base64');
    if (bytes[0] !== signatures.length) {
        throw new Error('fixture must use a single-byte compact signature count');
    }
    signatures.forEach((signature, index) => {
        const start = 1 + index * 64;
        bytes.fill(0, start, start + 64);
        if (signature) {
            bytes.set(signature, start);
        }
    });
    return bytes.toString('base64');
}

function idempotencyIdForMessage(messageBytes: ArrayLike<number>): string {
    const digest = createHash('sha256')
        .update(new Uint8Array(Array.from(messageBytes)))
        .digest()
        .subarray(0, 16);
    digest[6] = (digest[6]! & 0x0f) | 0x40;
    digest[8] = (digest[8]! & 0x3f) | 0x80;
    const hex = digest.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function mockVaultResponse(address: string = MOCK_ADDRESS) {
    return new Response(JSON.stringify({ address, id: 'test-vault-id' }), { status: 200 });
}

/**
 * Queue the vault-verification fetch that `FordefiSigner.create()` performs.
 * Must be called before any additional `mockResolvedValueOnce` chains because
 * mocks are consumed FIFO.
 */
function setupCreateVaultMock(address: string = MOCK_ADDRESS) {
    vi.mocked(fetch).mockResolvedValueOnce(mockVaultResponse(address));
}

describe('FordefiSigner', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    describe('create', () => {
        it('should create a signer with valid config', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        it('should satisfy the SolanaSigner interface', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            expect(() => assertIsSolanaSigner(signer)).not.toThrow();
        });

        it('should infer and expose the native manual signer interface', async () => {
            setupCreateVaultMock();
            const signer = await createFordefiSigner(nativeManualConfig);
            expectTypeOf(signer).toMatchTypeOf<FordefiNativeManualSigner>();
            expect(typeof signer.modifyAndSignTransactions).toBe('function');
        });

        it('should infer the black-box and native-auto signer interfaces', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(mockVaultResponse()).mockResolvedValueOnce(mockVaultResponse());

            const blackBoxSigner = await createFordefiSigner(mockConfig);
            const nativeAutoSigner = await createFordefiSigner(nativeConfig);

            expectTypeOf(blackBoxSigner).toMatchTypeOf<SolanaSigner>();
            expectTypeOf(nativeAutoSigner).toMatchTypeOf<FordefiNativeSigner>();
        });

        it('should reject manual push mode without a chain before any network call', async () => {
            await expect(
                FordefiSigner.create({
                    ...mockConfig,
                    pushMode: 'manual',
                } as unknown as FordefiManualSignerConfig),
            ).rejects.toMatchObject({ code: 'SIGNER_CONFIG_ERROR' });
            expect(fetch).not.toHaveBeenCalled();
        });

        it('should derive address from public_key_compressed for black box vaults', async () => {
            // Simulate a black box vault response with no address field.
            // Use base58-decode of MOCK_ADDRESS as the compressed key bytes.
            const { getBase58Encoder } = await import('@solana/codecs-strings');
            const keyBytes = getBase58Encoder().encode(MOCK_ADDRESS);
            const compressedB64 = Buffer.from(keyBytes).toString('base64');

            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        id: 'test-vault-id',
                        public_key_compressed: compressedB64,
                        type: 'black_box',
                    }),
                    { status: 200 },
                ),
            );
            const signer = await FordefiSigner.create(mockConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        it('should reject when vault address does not match configured publicKey', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        address: '22222222222222222222222222222222',
                        id: 'test-vault-id',
                    }),
                    { status: 200 },
                ),
            );
            await expect(FordefiSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });

        it('should reject when vault response omits address and public_key_compressed', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ id: 'test-vault-id' }), { status: 200 }),
            );
            await expect(FordefiSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });

        it('should reject when vault fetch returns non-OK', async () => {
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );
            await expect(FordefiSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
            });
        });

        it('should reject when vault fetch network-errors', async () => {
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network down'));
            await expect(FordefiSigner.create(mockConfig)).rejects.toMatchObject({
                code: 'SIGNER_HTTP_ERROR',
            });
        });

        it('should throw on empty accessToken', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, accessToken: '' })).rejects.toThrow();
        });

        it('should throw on empty vaultId', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, vaultId: '' })).rejects.toThrow();
        });

        it('should throw on empty publicKey', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, publicKey: '' })).rejects.toThrow();
        });

        it('should throw on HTTP apiBaseUrl', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, apiBaseUrl: 'http://insecure.com' })).rejects.toThrow();
        });

        it('should throw on invalid PEM', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, privateKeyPem: 'not-a-pem' })).rejects.toThrow();
        });

        it('should throw on invalid publicKey format', async () => {
            await expect(FordefiSigner.create({ ...mockConfig, publicKey: 'not-a-pubkey' })).rejects.toThrow();
        });

        it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
            'should reject invalid maxPollAttempts %s before any network call',
            async maxPollAttempts => {
                await expect(FordefiSigner.create({ ...mockConfig, maxPollAttempts })).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                });
                expect(fetch).not.toHaveBeenCalled();
            },
        );

        it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
            'should reject invalid pollIntervalMs %s before any network call',
            async pollIntervalMs => {
                await expect(FordefiSigner.create({ ...mockConfig, pollIntervalMs })).rejects.toMatchObject({
                    code: 'SIGNER_CONFIG_ERROR',
                });
                expect(fetch).not.toHaveBeenCalled();
            },
        );
    });

    describe('modifyAndSignTransactions (native manual mode)', () => {
        it.each(['legacy', 0, 1] as const)(
            'returns a signed, lifetime-bearing transaction from a %s envelope without broadcasting',
            async version => {
                const { config, fixture, transaction } = await setupNativeManual(version);
                vi.mocked(fetch)
                    .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                    .mockResolvedValueOnce(mockCreateTxResponse('tx-manual'))
                    .mockResolvedValueOnce(
                        mockPollResponse(
                            version === 1 ? 'completed' : 'signed',
                            MOCK_SIGNATURE_BASE64,
                            fixture.wireTransaction,
                        ),
                    );

                const signer = await FordefiSigner.create(config);
                const [result] = await signer.modifyAndSignTransactions([transaction]);

                expect(result?.messageBytes).toStrictEqual(fixture.messageBytes);
                expect(result?.signatures[fixture.feePayer]).toStrictEqual(fixture.signature);
                expect(result?.lifetimeConstraint).toEqual({
                    blockhash: MOCK_ADDRESS,
                    lastValidBlockHeight: 100n,
                });
                expect(assertSignatureValid).toHaveBeenCalledWith({
                    data: fixture.messageBytes,
                    signature: fixture.signature,
                    signerAddress: fixture.feePayer,
                });

                const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
                const body = JSON.parse(postOpts.body as string);
                expect(body.details.push_mode).toBe('manual');
                expect(body.details.type).toBe('solana_serialized_transaction_message');
                expect(fetch).toHaveBeenCalledTimes(3);
            },
        );

        it('exposes only the modifying transaction method', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeManualConfig);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            expect(isTransactionModifyingSigner(guardInput)).toBe(true);
            expect(isTransactionPartialSigner(guardInput)).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(false);
            expect(isSolanaSigner(guardInput)).toBe(false);
            expect(isSolanaSendingSigner(guardInput)).toBe(false);
            expect('signTransactions' in signer).toBe(false);
            expect('signAndSendTransactions' in signer).toBe(false);
        });

        it('retains native Solana personal-message signing', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('msg-manual'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(nativeManualConfig);
            await signer.signMessages([{ content: new Uint8Array(32), signatures: {} }]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('solana_message');
            expect(body.details.type).toBe('personal_message_type');
            expect(body.details.chain).toBe('solana_mainnet');
        });

        it('namespaces deterministic manual idempotency away from auto mode', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            const namespace = Buffer.from(`fordefi:solana:manual:${config.chain}:${config.vaultId}:`, 'utf8');
            const digest = createHash('sha256')
                .update(Buffer.concat([namespace, Buffer.from(transaction.messageBytes)]))
                .digest()
                .subarray(0, 16);
            digest[6] = (digest[6]! & 0x0f) | 0x40;
            digest[8] = (digest[8]! & 0x3f) | 0x80;
            const hex = digest.toString('hex');
            const expectedId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;

            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-id'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create(config);
            await signer.modifyAndSignTransactions([transaction]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-idempotence-id', expectedId);
            expect(expectedId).not.toBe(idempotencyIdForMessage(transaction.messageBytes));
        });

        it('uses Kit unknown-height lifetime when Fordefi replaces the lifetime token', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            const originalWithDifferentLifetime = {
                ...transaction,
                lifetimeConstraint: {
                    blockhash: '22222222222222222222222222222222',
                    lastValidBlockHeight: 50n,
                },
                messageBytes: new Uint8Array(transaction.messageBytes).fill(
                    transaction.messageBytes[transaction.messageBytes.length - 1]! ^ 0x01,
                    transaction.messageBytes.length - 1,
                ),
            } as unknown as Transaction & TransactionWithLifetime;
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-new-lifetime'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create(config);
            const [result] = await signer.modifyAndSignTransactions([originalWithDifferentLifetime]);

            expect(result?.messageBytes).toStrictEqual(fixture.messageBytes);
            expect(result?.lifetimeConstraint).toEqual({
                blockhash: MOCK_ADDRESS,
                lastValidBlockHeight: 0xffffffffffffffffn,
            });
        });

        it('supports unsigned downstream signer slots in manual mode', async () => {
            const fixture = await createCosignedWireTransaction(0);
            const manualWire = replaceLegacyWireSignatures(fixture.wireTransaction, [MOCK_SIGNATURE_BYTES, null]);
            const config = {
                ...mockConfig,
                chain: 'solana_mainnet',
                publicKey: fixture.feePayer,
                pushMode: 'manual',
            } satisfies FordefiManualSignerConfig;
            const transaction = {
                lifetimeConstraint: { blockhash: MOCK_ADDRESS, lastValidBlockHeight: 100n },
                messageBytes: Buffer.from(manualWire, 'base64').subarray(129),
                signatures: { [fixture.feePayer]: null, [fixture.cosigner]: null },
            } as unknown as Transaction & TransactionWithLifetime;
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-cosign'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, manualWire));

            const signer = await FordefiSigner.create(config);
            const [result] = await signer.modifyAndSignTransactions([transaction]);

            expect(result?.signatures[fixture.feePayer]).toStrictEqual(MOCK_SIGNATURE_BYTES);
            expect(result?.signatures[fixture.cosigner]).toBeNull();
        });

        it('signs batches with the configured request delay', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-1'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-2'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create({ ...config, requestDelayMs: 1 });
            const results = await signer.modifyAndSignTransactions([transaction, transaction]);

            expect(results).toHaveLength(2);
            expect(fetch).toHaveBeenCalledTimes(5);
        });

        it('rejects pre-signed input before submitting remote work', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            setupCreateVaultMock(fixture.feePayer);
            const signer = await FordefiSigner.create(config);
            const preSigned = {
                ...transaction,
                signatures: { [fixture.feePayer]: fixture.signature },
            } as unknown as Transaction & TransactionWithLifetime;

            await expect(signer.modifyAndSignTransactions([preSigned])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
            expect(fetch).toHaveBeenCalledTimes(1);
        });

        it('rejects a non-Fordefi fee payer before submitting remote work', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeManualConfig);
            const transaction = {
                messageBytes: new Uint8Array(32),
                signatures: { '22222222222222222222222222222222': null, [MOCK_ADDRESS]: null },
            } as never;

            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
            expect(fetch).toHaveBeenCalledTimes(1);
        });

        it('honors an already-aborted signal without submitting remote work', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            setupCreateVaultMock(fixture.feePayer);
            const signer = await FordefiSigner.create(config);
            const controller = new AbortController();
            controller.abort();

            await expect(
                signer.modifyAndSignTransactions([transaction], { abortSignal: controller.signal }),
            ).rejects.toThrow();
            expect(fetch).toHaveBeenCalledTimes(1);
        });

        it('aborts an in-flight manual submission', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            const controller = new AbortController();
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockImplementationOnce((_input, init) => {
                    const signal = init?.signal as AbortSignal;
                    return new Promise<Response>((_resolve, reject) => {
                        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
                        controller.abort(new Error('stop manual signing'));
                    });
                });

            const signer = await FordefiSigner.create(config);
            await expect(
                signer.modifyAndSignTransactions([transaction], { abortSignal: controller.signal }),
            ).rejects.toMatchObject({ code: 'SIGNER_HTTP_ERROR' });
            expect(fetch).toHaveBeenCalledTimes(2);
        });

        it('reports manual signing failures without broadcast-unconfirmed wrapping', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-fail'))
                .mockResolvedValueOnce(mockPollResponse('error_signing'));

            const signer = await FordefiSigner.create(config);
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('times out while waiting for a manual signature', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-timeout'))
                .mockResolvedValueOnce(mockPollResponse('pending_signature'))
                .mockResolvedValueOnce(mockPollResponse('pending_signature'));

            const signer = await FordefiSigner.create({
                ...config,
                maxPollAttempts: 2,
                pollIntervalMs: 1,
            });
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_REMOTE_API_ERROR',
            });
        });

        it('rejects a manual response whose vault signature does not verify', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-invalid-signature'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));
            vi.mocked(assertSignatureValid).mockRejectedValueOnce(new Error('invalid signature'));

            const signer = await FordefiSigner.create(config);
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toThrow('invalid signature');
        });

        it('passes native fee configuration in manual mode', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-fee'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create({
                ...config,
                fee: { priority_fee: '1000', type: 'custom' },
            });
            await signer.modifyAndSignTransactions([transaction]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.details.fee).toEqual({ priority_fee: '1000', type: 'custom' });
        });

        it('rejects missing and malformed manual raw transactions', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-no-raw'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64));
            const signer = await FordefiSigner.create(config);
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });

            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-malformed'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, 'AQID'));
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_PARSING_ERROR',
            });
        });

        it('rejects a manual wire transaction missing the Fordefi signature', async () => {
            const fixture = await createCosignedWireTransaction(0);
            const config = {
                ...mockConfig,
                chain: 'solana_mainnet',
                publicKey: fixture.feePayer,
                pushMode: 'manual',
            } satisfies FordefiManualSignerConfig;
            const messageBytes = Buffer.from(fixture.wireTransaction, 'base64').subarray(129);
            const transaction = {
                lifetimeConstraint: { blockhash: MOCK_ADDRESS, lastValidBlockHeight: 100n },
                messageBytes,
                signatures: { [fixture.feePayer]: null, [fixture.cosigner]: null },
            } as never;
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-no-vault-sig'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create(config);
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('rejects an oversized returned manual transaction', async () => {
            const { config, fixture, transaction } = await setupNativeManual(0);
            const oversizedWire = Buffer.concat([
                Buffer.from(fixture.wireTransaction, 'base64'),
                Buffer.alloc(2_000),
            ]).toString('base64');
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-manual-oversized'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64, oversizedWire));

            const signer = await FordefiSigner.create(config);
            await expect(signer.modifyAndSignTransactions([transaction])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });
    });

    describe('custom requestSigner', () => {
        // Config using a custom request signer instead of a PEM key.
        const customConfig: FordefiSignerConfig & { chain?: undefined } = {
            accessToken: 'test-token',
            apiBaseUrl: 'https://api.test.fordefi.com',
            publicKey: MOCK_ADDRESS,
            requestSigner: { signRequest: () => 'custom-sig-value' },
            vaultId: 'test-vault-id',
        };

        it('should create a signer without privateKeyPem when requestSigner is provided', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(customConfig);
            expect(signer.address).toBe(MOCK_ADDRESS);
        });

        it('should set x-signature from the custom requestSigner output', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(customConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await signer.signTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-signature', 'custom-sig-value');
        });

        it('should support an async requestSigner', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create({
                ...customConfig,
                requestSigner: { signRequest: async () => 'async-sig-value' },
            });
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await signer.signTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-signature', 'async-sig-value');
        });

        it('should reject when neither privateKeyPem nor requestSigner is provided', async () => {
            await expect(FordefiSigner.create({ ...customConfig, requestSigner: undefined })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });

        it('should reject when both privateKeyPem and requestSigner are provided', async () => {
            await expect(FordefiSigner.create({ ...customConfig, privateKeyPem: TEST_PEM })).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
        });
    });

    describe('signTransactions', () => {
        it('should sign a transaction via black box submit + poll', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            const results = await signer.signTransactions([mockTx]);
            expect(results).toHaveLength(1);
            expect(results[0]).toHaveProperty(MOCK_ADDRESS);

            // Verify POST was called with black_box_signature format (call #2; #1 is vault)
            expect(fetch).toHaveBeenCalledTimes(3);
            const call = vi.mocked(fetch).mock.calls[1]!;
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
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32).fill(0x11) } as never;

            const results = await signer.signTransactions([mockTx]);

            expect(results[0]).toHaveProperty(MOCK_ADDRESS);
            expect(Object.values(results[0]!)[0]).toEqual(MOCK_SIGNATURE_BYTES);
        });

        it('should handle failed transaction state', async () => {
            setupCreateVaultMock();
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse('error_signing'));

            const signer = await FordefiSigner.create(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        it('should timeout after max poll attempts', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create({
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            const mockTx = { messageBytes: new Uint8Array(32) } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toThrow();
        });

        // Black-box mode only signs, so a failed submit has no on-chain outcome to be unconfirmed about.
        it('does not report a 5xx on a black-box submit as unconfirmed', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
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
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('msg-1'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(mockConfig);
            const results = await signer.signMessages([{ content: new Uint8Array(32), signatures: {} }]);
            expect(results).toHaveLength(1);

            // Verify request body uses the black_box_signature schema (call #2)
            expect(fetch).toHaveBeenCalledTimes(3);
            const call = vi.mocked(fetch).mock.calls[1]!;
            expect(call[0]).toBe('https://api.test.fordefi.com/api/v1/transactions');
            const postOpts = call[1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('black_box_signature');
            expect(body.details.format).toBe('hash_binary');
            expect(body.details).toHaveProperty('hash_binary');
        });

        it('should sign multiple messages serially with delay', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('msg-1'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64))
                .mockResolvedValueOnce(mockCreateTxResponse('msg-2'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create({ ...mockConfig, requestDelayMs: 1 });
            const results = await signer.signMessages([
                { content: new Uint8Array(32), signatures: {} },
                { content: new Uint8Array(32), signatures: {} },
            ]);
            expect(results).toHaveLength(2);
            expect(fetch).toHaveBeenCalledTimes(5);
        });

        it('should throw when completed state has no signatures', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-empty'))
                .mockResolvedValueOnce(mockPollResponse('completed'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on failed state', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-fail'))
                .mockResolvedValueOnce(mockPollResponse('aborted'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on submit API error', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(
                new Response(JSON.stringify({ message: 'Unauthorized' }), { status: 401 }),
            );

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toThrow();
        });

        it('should throw on signature with wrong byte length', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
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
                    .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                    .mockResolvedValueOnce(mockCreateTxResponse('tx-native'))
                    .mockResolvedValueOnce(
                        mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction),
                    );

                const signer = await FordefiSigner.create(config);
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

                // Verify POST body uses solana_transaction type
                const call = vi.mocked(fetch).mock.calls[1]!;
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
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-native'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create(config);
            const mockTx = { messageBytes, signatures: { [fixture.feePayer]: null } } as never;
            await signer.signAndSendTransactions([mockTx]);

            const postOpts = vi.mocked(fetch).mock.calls[1]![1] as RequestInit;
            expect(postOpts.headers).toHaveProperty('x-idempotence-id', expectedId);
        });

        it('does not expose the partial-signer method in native mode', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            // Kit classifies by method presence: a present-but-throwing
            // signTransactions would make Kit partial-sign and fail at runtime.
            expect(signer.signTransactions).toBeUndefined();
            expect('signTransactions' in signer).toBe(false);
            expect(isTransactionPartialSigner(guardInput)).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(true);
            expect(isSolanaSigner(guardInput)).toBe(false);
            expect(isSolanaSendingSigner(guardInput)).toBe(true);
        });

        it('should reject native multi-signer auto-broadcast before submitting remote work', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
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
            expect(fetch).toHaveBeenCalledTimes(1);
        });

        it('should not expose TransactionSendingSigner in black box mode', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            const guardInput = signer as unknown as { [key: string]: unknown; address: typeof signer.address };

            expect('signAndSendTransactions' in signer).toBe(false);
            expect(isTransactionSendingSigner(guardInput)).toBe(false);
            expect(isTransactionPartialSigner(guardInput)).toBe(true);
            expect(isSolanaSigner(guardInput)).toBe(true);
            expect(isSolanaSendingSigner(guardInput)).toBe(false);
        });

        it('should poll through intermediate pushable states', async () => {
            const { config, fixture } = await setupNativeBroadcast(1);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse(fixture.feePayer))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-push'))
                .mockResolvedValueOnce(mockPollResponse('pushing'))
                .mockResolvedValueOnce(mockPollResponse('confirming'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create({ ...config, pollIntervalMs: 1 });
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [fixture.feePayer]: null },
            } as never;
            const results = await signer.signAndSendTransactions([mockTx]);
            expect(results).toHaveLength(1);
            expect(fetch).toHaveBeenCalledTimes(5);
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
                .mockResolvedValueOnce(mockVaultResponse(fixture.cosigner))
                .mockResolvedValueOnce(mockCreateTxResponse('tx-unsigned-payer'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, fixture.wireTransaction));

            const signer = await FordefiSigner.create(config);
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
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
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-no-raw'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(nativeConfig);
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
            setupCreateVaultMock();
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('tx-fail'))
                .mockResolvedValueOnce(mockPollResponse('mined_reverted'));

            const signer = await FordefiSigner.create(nativeConfig);
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
            setupCreateVaultMock();
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse())
                .mockResolvedValueOnce(mockPollResponse(state));

            const signer = await FordefiSigner.create(mockConfig);
            const mockTx = { messageBytes: new Uint8Array(32) } as never;
            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });
    });

    describe('signMessages (native solana mode)', () => {
        it('should submit solana_message with personal_message_type', async () => {
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('msg-native'))
                .mockResolvedValueOnce(mockPollResponse('signed', MOCK_SIGNATURE_BASE64));

            const signer = await FordefiSigner.create(nativeConfig);
            const results = await signer.signMessages([{ content: new Uint8Array(32), signatures: {} }]);
            expect(results).toHaveLength(1);

            // Verify POST body uses solana_message type
            const call = vi.mocked(fetch).mock.calls[1]!;
            const postOpts = call[1] as RequestInit;
            const body = JSON.parse(postOpts.body as string);
            expect(body.type).toBe('solana_message');
            expect(body.details.type).toBe('personal_message_type');
            expect(body.details.chain).toBe('solana_mainnet');
            expect(body.details).toHaveProperty('raw_data');
        });

        it('should throw when completed state has no signatures', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockCreateTxResponse('msg-empty'))
                .mockResolvedValueOnce(mockPollResponse('signed'));

            await expect(signer.signMessages([{ content: new Uint8Array(32), signatures: {} }])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('should throw on aborted state', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
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
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(mockVaultResponse());
            expect(await signer.isAvailable()).toBe(true);
        });

        it('should return false on API error', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch).mockResolvedValueOnce(new Response(null, { status: 500 }));
            expect(await signer.isAvailable()).toBe(false);
        });

        it('should return false on network error', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(mockConfig);
            vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));
            expect(await signer.isAvailable()).toBe(false);
        });
    });
});
