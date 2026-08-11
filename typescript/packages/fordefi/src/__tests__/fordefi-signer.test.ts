import { generateKeyPairSync } from 'node:crypto';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { type Address } from '@solana/addresses';
import { AccountRole, type Instruction } from '@solana/instructions';
import { assertIsSolanaSigner, assertSignatureValid, extractSignatureFromWireTransaction } from '@solana/keychain-core';
import { isTransactionSendingSigner } from '@solana/signers';
import {
    appendTransactionMessageInstruction,
    compileTransactionMessage,
    createTransactionMessage,
    getCompiledTransactionMessageEncoder,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/transaction-messages';

vi.mock('@solana/keychain-core', async importOriginal => {
    const mod = await importOriginal<typeof import('@solana/keychain-core')>();
    return {
        ...mod,
        assertSignatureValid: vi.fn(),
        // Stub extraction so we don't need to craft a byte-exact Solana
        // wire transaction for the happy-path tests. The real extraction
        // logic lives in @solana/keychain-core and is covered there.
        extractSignatureFromWireTransaction: vi.fn(({ signerAddress }: { signerAddress: string }) =>
            Object.freeze({ [signerAddress]: new Uint8Array(64).fill(0xab) }),
        ),
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

import { FordefiSigner, type FordefiSignerConfig } from '../fordefi-signer.js';

// Mock fetch globally
global.fetch = vi.fn();

const MOCK_ADDRESS = '11111111111111111111111111111111';

// Generate a real P-256 key pair for tests
const { privateKey: testPrivateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const TEST_PEM = testPrivateKey.export({ type: 'sec1', format: 'pem' }) as string;

const MOCK_SIGNATURE_BYTES = new Uint8Array(64).fill(0xab);
const MOCK_SIGNATURE_BASE64 = Buffer.from(MOCK_SIGNATURE_BYTES).toString('base64');

const mockConfig: FordefiSignerConfig = {
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

const COMPUTE_BUDGET_PROGRAM_ADDRESS = 'ComputeBudget111111111111111111111111111111' as Address;
const RECIPIENT_ADDRESS = 'SysvarC1ock11111111111111111111111111111111' as Address;
const OTHER_RECIPIENT_ADDRESS = 'SysvarRent111111111111111111111111111111111' as Address;
type TestBlockhash = Parameters<typeof setTransactionMessageLifetimeUsingBlockhash>[0]['blockhash'];
const MOCK_BLOCKHASH = '11111111111111111111111111111111' as TestBlockhash;
const FRESH_BLOCKHASH = 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi' as TestBlockhash;

/** A System-transfer-shaped instruction: one writable-signer payer, one writable recipient. */
function transferInstruction(recipient: Address, lamports: number): Instruction {
    return {
        accounts: [
            { address: MOCK_ADDRESS as Address, role: AccountRole.WRITABLE_SIGNER },
            { address: recipient, role: AccountRole.WRITABLE },
        ],
        data: new Uint8Array([2, 0, 0, 0, lamports, 0, 0, 0, 0, 0, 0, 0]),
        programAddress: '11111111111111111111111111111112' as Address,
    };
}

function setComputeUnitPriceInstruction(microLamports = 5000): Instruction {
    const data = new Uint8Array(9);
    data[0] = 3;
    new DataView(data.buffer).setBigUint64(1, BigInt(microLamports), true);
    return { data, programAddress: COMPUTE_BUDGET_PROGRAM_ADDRESS };
}

function requestHeapFrameInstruction(): Instruction {
    const data = new Uint8Array(5);
    data[0] = 1;
    new DataView(data.buffer).setUint32(1, 256 * 1024, true);
    return { data, programAddress: COMPUTE_BUDGET_PROGRAM_ADDRESS };
}

/** Compile a real legacy transaction message and return its wire message bytes. */
function compiledMessageBytes(
    instructions: readonly Instruction[],
    blockhash: TestBlockhash = MOCK_BLOCKHASH,
    feePayer: Address = MOCK_ADDRESS as Address,
): Uint8Array<ArrayBuffer> {
    const message = instructions.reduce(
        (acc, instruction) => appendTransactionMessageInstruction(instruction, acc),
        setTransactionMessageLifetimeUsingBlockhash(
            { blockhash, lastValidBlockHeight: 100n },
            setTransactionMessageFeePayer(feePayer, createTransactionMessage({ version: 'legacy' })),
        ) as Parameters<typeof appendTransactionMessageInstruction>[1],
    );
    const encoded = getCompiledTransactionMessageEncoder().encode(compileTransactionMessage(message as never));
    const bytes = new Uint8Array(encoded.length);
    bytes.set(encoded);
    return bytes;
}

/** A submitted transaction carrying a single transfer, as the caller would build it. */
function mockNativeTransaction(recipient: Address = RECIPIENT_ADDRESS, lamports = 1_000_000): never {
    return {
        messageBytes: compiledMessageBytes([transferInstruction(recipient, lamports)]),
        signatures: { [MOCK_ADDRESS]: null },
    } as never;
}

/** Build a fake base64 wire transaction (1-byte sig count + 64-byte sig + message). */
function mockWireTransaction(messageBytes = new Uint8Array(32)): string {
    const wire = new Uint8Array(1 + 64 + messageBytes.length);
    wire[0] = 1;
    wire.set(new Uint8Array(64).fill(0xab), 1);
    wire.set(messageBytes, 65);
    return Buffer.from(wire).toString('base64');
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

    describe('custom requestSigner', () => {
        // Config using a custom request signer instead of a PEM key.
        const customConfig: FordefiSignerConfig = {
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

            expect(vi.mocked(extractSignatureFromWireTransaction)).not.toHaveBeenCalled();
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
        it('should expose a TransactionSendingSigner and return the broadcast transaction signature', async () => {
            // Fordefi's own rewrite: same instruction, freshly stamped blockhash.
            const returnedMessage = compiledMessageBytes(
                [transferInstruction(RECIPIENT_ADDRESS, 1_000_000)],
                FRESH_BLOCKHASH,
            );
            const wireTx = mockWireTransaction(returnedMessage);
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-native'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            expect(
                isTransactionSendingSigner(
                    signer as unknown as { [key: string]: unknown; address: typeof signer.address },
                ),
            ).toBe(true);

            const mockTx = mockNativeTransaction();
            const results = await signer.signAndSendTransactions([mockTx]);
            expect(results).toHaveLength(1);
            expect(results[0]).toEqual(MOCK_SIGNATURE_BYTES);
            expect(assertSignatureValid).toHaveBeenCalledWith(
                expect.objectContaining({
                    data: returnedMessage,
                    signerAddress: MOCK_ADDRESS,
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
        });

        it('should reject partial-signer usage before submitting native remote work', async () => {
            setupCreateVaultMock();
            const signer = await FordefiSigner.create(nativeConfig);
            const mockTx = {
                messageBytes: new Uint8Array(32),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;

            await expect(signer.signTransactions([mockTx])).rejects.toMatchObject({
                code: 'SIGNER_CONFIG_ERROR',
            });
            expect(fetch).toHaveBeenCalledTimes(1);
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
            expect(
                isTransactionSendingSigner(
                    signer as unknown as { [key: string]: unknown; address: typeof signer.address },
                ),
            ).toBe(false);
        });

        it('should poll through intermediate pushable states', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes([transferInstruction(RECIPIENT_ADDRESS, 1_000_000)], FRESH_BLOCKHASH),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-push'))
                .mockResolvedValueOnce(mockPollResponse('pushing'))
                .mockResolvedValueOnce(mockPollResponse('confirming'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create({ ...nativeConfig, pollIntervalMs: 1 });
            const results = await signer.signAndSendTransactions([mockNativeTransaction()]);
            expect(results).toHaveLength(1);
            expect(fetch).toHaveBeenCalledTimes(5);
        });

        /**
         * Fordefi sets the priority fee itself when the submitted message carries no
         * ComputeBudget instructions, so those additions must not be rejected.
         */
        it('should accept a returned transaction with added ComputeBudget instructions', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes(
                    [setComputeUnitPriceInstruction(), transferInstruction(RECIPIENT_ADDRESS, 1_000_000)],
                    FRESH_BLOCKHASH,
                ),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-fee'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            const results = await signer.signAndSendTransactions([mockNativeTransaction()]);
            expect(results).toHaveLength(1);
        });

        /**
         * Fordefi only sets fees for requests carrying no ComputeBudget instructions,
         * so an addition alongside caller-supplied compute controls is a substitution.
         */
        it('should reject added fee instructions when the request already had ComputeBudget', async () => {
            const submitted = {
                messageBytes: compiledMessageBytes([
                    setComputeUnitPriceInstruction(10),
                    transferInstruction(RECIPIENT_ADDRESS, 1_000_000),
                ]),
                signatures: { [MOCK_ADDRESS]: null },
            } as never;
            const wireTx = mockWireTransaction(
                compiledMessageBytes(
                    [
                        setComputeUnitPriceInstruction(10),
                        setComputeUnitPriceInstruction(10_000_000),
                        transferInstruction(RECIPIENT_ADDRESS, 1_000_000),
                    ],
                    FRESH_BLOCKHASH,
                ),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-double-fee'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([submitted])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        /**
         * Only SetComputeUnitLimit and SetComputeUnitPrice are fee-setting; a
         * RequestHeapFrame addition is not something Fordefi does.
         */
        it('should reject a non-fee ComputeBudget addition', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes(
                    [requestHeapFrameInstruction(), transferInstruction(RECIPIENT_ADDRESS, 1_000_000)],
                    FRESH_BLOCKHASH,
                ),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-heap'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([mockNativeTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        /**
         * A different transaction signed by the same vault must not be reported as a
         * successful signing of the submitted one.
         */
        it('should reject a returned transaction with a substituted recipient', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes([transferInstruction(OTHER_RECIPIENT_ADDRESS, 1_000_000)], FRESH_BLOCKHASH),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-swap'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([mockNativeTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('should reject a returned transaction with a changed lamport amount', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes([transferInstruction(RECIPIENT_ADDRESS, 250)], FRESH_BLOCKHASH),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-amount'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([mockNativeTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('should reject a returned transaction that dropped the submitted instruction', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes([setComputeUnitPriceInstruction()], FRESH_BLOCKHASH),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-dropped'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([mockNativeTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
        });

        it('should reject a returned transaction with a different fee payer', async () => {
            const wireTx = mockWireTransaction(
                compiledMessageBytes(
                    [transferInstruction(RECIPIENT_ADDRESS, 1_000_000)],
                    FRESH_BLOCKHASH,
                    OTHER_RECIPIENT_ADDRESS,
                ),
            );
            vi.mocked(fetch)
                .mockResolvedValueOnce(mockVaultResponse())
                .mockResolvedValueOnce(mockCreateTxResponse('tx-payer'))
                .mockResolvedValueOnce(mockPollResponse('completed', MOCK_SIGNATURE_BASE64, wireTx));

            const signer = await FordefiSigner.create(nativeConfig);
            await expect(signer.signAndSendTransactions([mockNativeTransaction()])).rejects.toMatchObject({
                code: 'SIGNER_SIGNING_FAILED',
            });
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
                code: 'SIGNER_SIGNING_FAILED',
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
                code: 'SIGNER_SIGNING_FAILED',
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
