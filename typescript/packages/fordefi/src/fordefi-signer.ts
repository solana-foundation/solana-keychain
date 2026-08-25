import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';

import { Address, assertIsAddress } from '@solana/addresses';
import {
    getBase58Decoder,
    getBase58Encoder,
    getBase64Decoder,
    getBase64Encoder,
    getUtf8Encoder,
} from '@solana/codecs-strings';
import {
    abortableDelay,
    assertHttpsUrl,
    assertSignatureValid,
    createSignatureDictionary,
    ED25519_SIGNATURE_LENGTH,
    fetchSignerJson,
    idempotencyKeyFromMessage,
    normalizeBaseUrl,
    providerMayHaveAccepted,
    providerStatus,
    signBatchStaggered,
    SignerErrorCode,
    SolanaModifyingSigner,
    SolanaSendingSigner,
    SolanaSigner,
    throwSignerError,
    validateRequestDelayMs,
} from '@solana/keychain-core';
import { SignatureBytes } from '@solana/keys';
import {
    MessagePartialSigner,
    MessagePartialSignerConfig,
    SignableMessage,
    SignatureDictionary,
    TransactionModifyingSigner,
    TransactionModifyingSignerConfig,
    TransactionPartialSigner,
    TransactionPartialSignerConfig,
    TransactionSendingSigner,
    TransactionSendingSignerConfig,
} from '@solana/signers';
import {
    type CompiledTransactionMessage,
    type CompiledTransactionMessageWithLifetime,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
} from '@solana/transaction-messages';
import {
    assertIsTransactionWithinSizeLimit,
    Base64EncodedWireTransaction,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionLifetimeConstraintFromCompiledTransactionMessage,
    Transaction,
    TransactionWithinSizeLimit,
    TransactionWithLifetime,
} from '@solana/transactions';
import { COMPUTE_BUDGET_PROGRAM_ADDRESS } from '@solana-program/compute-budget';

import type {
    FordefiBlackBoxSignatureRequest,
    FordefiCreateTransactionResponse,
    FordefiSolanaFee,
    FordefiSolanaMessageRequest,
    FordefiSolanaTransactionRequest,
    FordefiTransactionStatusResponse,
    FordefiVaultResponse,
    SolanaChainUniqueId,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.fordefi.com';
const DEFAULT_POLL_INTERVAL_MS = 2000;

let base58Decoder: ReturnType<typeof getBase58Decoder> | undefined;
let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;
let base64Decoder: ReturnType<typeof getBase64Decoder> | undefined;
let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;
let utf8Encoder: ReturnType<typeof getUtf8Encoder> | undefined;
const DEFAULT_MAX_POLL_ATTEMPTS = 50;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SET_COMPUTE_UNIT_LIMIT = 2;
const SET_COMPUTE_UNIT_PRICE = 3;
const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
const MICRO_LAMPORTS_PER_LAMPORT = 1_000_000n;
/**
 * Default ceiling, in lamports, on a priority fee Fordefi introduces itself
 * during native manual signing, so a compromised or malfunctioning response
 * cannot drain the fee payer. Override via
 * {@link FordefiSignerConfig.maxPriorityFeeLamports}.
 */
export const DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 100_000_000n;

// Validated at runtime: an unrecognized value would fall through to auto and
// broadcast.
const PUSH_MODES = new Set(['auto', 'manual']);
/** Terminal success states for pushable transactions (solana_transaction with push_mode auto). */
const PUSHABLE_SUCCESS_STATES = new Set(['completed']);
/** Terminal success states for non-pushable transactions (black box, messages, and native manual). */
const NON_PUSHABLE_SUCCESS_STATES = new Set(['signed', 'completed']);
/** Terminal failure states (all transaction types). Mirrors the Rust backend. */
const FAILURE_STATES = new Set([
    'aborted',
    'cancelled',
    'completed_reverted',
    'dropped',
    'error_pushing_to_blockchain',
    'error_signing',
    'insufficient_funds',
    'mined_reverted',
]);

type DecodedCompiledMessage = CompiledTransactionMessage & CompiledTransactionMessageWithLifetime;
type LegacyOrV0CompiledMessage = Extract<DecodedCompiledMessage, { version: 'legacy' | 0 }>;
type MutableCompiledInstruction = {
    accountIndices?: number[];
    data?: Uint8Array;
    programAddressIndex: number;
};
type ManualFeeInstructions = { limit?: number; price?: bigint };
type ManualFeePolicy = { fee?: FordefiSolanaFee; maxPriorityFeeLamports?: bigint };

function bytesEqual(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

function encodeCompiledMessage(message: DecodedCompiledMessage): ArrayLike<number> {
    return getCompiledTransactionMessageEncoder().encode(message);
}

function compareManualMessagesExactly(
    original: DecodedCompiledMessage,
    returned: DecodedCompiledMessage,
    allowBlockhashReplacement: boolean,
): boolean {
    const comparable = allowBlockhashReplacement
        ? ({ ...returned, lifetimeToken: original.lifetimeToken } as DecodedCompiledMessage)
        : returned;
    return bytesEqual(encodeCompiledMessage(original), encodeCompiledMessage(comparable));
}

function normalizeManualFeeMessage(message: LegacyOrV0CompiledMessage): {
    fees: ManualFeeInstructions;
    message: LegacyOrV0CompiledMessage;
} {
    const normalized = {
        ...message,
        header: { ...message.header },
        instructions: message.instructions.map(instruction => ({
            ...instruction,
            accountIndices: instruction.accountIndices ? [...instruction.accountIndices] : undefined,
            data: instruction.data ? new Uint8Array(instruction.data) : undefined,
        })),
        staticAccounts: [...message.staticAccounts],
    } as LegacyOrV0CompiledMessage & {
        header: {
            numReadonlyNonSignerAccounts: number;
            numReadonlySignerAccounts: number;
            numSignerAccounts: number;
        };
        instructions: MutableCompiledInstruction[];
        staticAccounts: Address[];
    };
    const fees: ManualFeeInstructions = {};
    const retained: MutableCompiledInstruction[] = [];

    for (const instruction of normalized.instructions) {
        const programAddress = normalized.staticAccounts[instruction.programAddressIndex];
        const opcode = instruction.data?.[0];
        if (
            programAddress !== COMPUTE_BUDGET_PROGRAM_ADDRESS ||
            (opcode !== SET_COMPUTE_UNIT_LIMIT && opcode !== SET_COMPUTE_UNIT_PRICE)
        ) {
            retained.push(instruction);
            continue;
        }
        if ((instruction.accountIndices?.length ?? 0) !== 0) {
            throw new Error('Fordefi returned an account-bearing Compute Budget fee instruction');
        }
        if (opcode === SET_COMPUTE_UNIT_LIMIT) {
            if (instruction.data?.length !== 5 || fees.limit !== undefined) {
                throw new Error('Fordefi returned a malformed or duplicate compute-unit limit');
            }
            const limit = Buffer.from(instruction.data).readUInt32LE(1);
            if (limit === 0 || limit > MAX_COMPUTE_UNIT_LIMIT) {
                throw new Error('Fordefi returned an out-of-range compute-unit limit');
            }
            fees.limit = limit;
        } else {
            if (instruction.data?.length !== 9 || fees.price !== undefined) {
                throw new Error('Fordefi returned a malformed or duplicate compute-unit price');
            }
            fees.price = Buffer.from(instruction.data).readBigUInt64LE(1);
        }
    }
    normalized.instructions = retained;

    const computeBudgetPositions = normalized.staticAccounts.flatMap((address, index) =>
        address === COMPUTE_BUDGET_PROGRAM_ADDRESS ? [index] : [],
    );
    if (computeBudgetPositions.length === 1) {
        const index = computeBudgetPositions[0]!;
        const readonlyNonSignerStart =
            normalized.staticAccounts.length - normalized.header.numReadonlyNonSignerAccounts;
        const referenced = normalized.instructions.some(
            instruction =>
                instruction.programAddressIndex === index || instruction.accountIndices?.includes(index) === true,
        );
        if (index >= normalized.header.numSignerAccounts && index >= readonlyNonSignerStart && !referenced) {
            normalized.staticAccounts.splice(index, 1);
            normalized.header.numReadonlyNonSignerAccounts--;
            for (const instruction of normalized.instructions) {
                if (instruction.programAddressIndex > index) {
                    instruction.programAddressIndex--;
                }
                instruction.accountIndices = instruction.accountIndices?.map(accountIndex =>
                    accountIndex > index ? accountIndex - 1 : accountIndex,
                );
            }
        }
    }
    return { fees, message: normalized };
}

/** Rounds up, and charges an absent limit at the runtime maximum. */
function effectivePriorityFeeLamports(fee: ManualFeeInstructions): bigint {
    const price = fee.price ?? 0n;
    const limit = BigInt(fee.limit ?? MAX_COMPUTE_UNIT_LIMIT);
    return (price * limit + MICRO_LAMPORTS_PER_LAMPORT - 1n) / MICRO_LAMPORTS_PER_LAMPORT;
}

/** `undefined` when a custom `priority_fee` already bounds the total. */
function manualPriorityFeeCeiling(policy: ManualFeePolicy): bigint | undefined {
    if (policy.maxPriorityFeeLamports !== undefined) return policy.maxPriorityFeeLamports;
    if (policy.fee?.type === 'custom' && policy.fee.priority_fee !== undefined) return undefined;
    return DEFAULT_MAX_PRIORITY_FEE_LAMPORTS;
}

/** Enforces {@link DEFAULT_MAX_PRIORITY_FEE_LAMPORTS} or the configured override. */
function validateManualFeeCeiling(policy: ManualFeePolicy, returned: ManualFeeInstructions): void {
    if (returned.price === undefined) return;
    const ceiling = manualPriorityFeeCeiling(policy);
    if (ceiling === undefined) return;
    if (effectivePriorityFeeLamports(returned) > ceiling) {
        throw new Error(
            'Fordefi returned a priority fee above the configured maximum; raise maxPriorityFeeLamports to allow it',
        );
    }
}

function validateManualCustomFee(fee: FordefiSolanaFee | undefined, returned: ManualFeeInstructions): void {
    if (fee?.type !== 'custom') return;
    if (fee.unit_price !== undefined) {
        const configuredPrice = BigInt(fee.unit_price);
        if (returned.price === undefined || returned.price !== configuredPrice) {
            throw new Error(
                'Fordefi returned a compute-unit price that does not match the configured custom unit_price',
            );
        }
    }
    if (fee.priority_fee !== undefined && returned.price !== undefined) {
        if (effectivePriorityFeeLamports(returned) > BigInt(fee.priority_fee)) {
            throw new Error('Fordefi returned a priority fee above the configured custom priority_fee');
        }
    }
}

/** Validate the mutation set Fordefi documents for an unsigned native manual request. */
async function manualMessagesMatchFordefiMutationPolicy(
    originalMessageBytes: Uint8Array,
    returnedMessageBytes: Uint8Array,
    policy: ManualFeePolicy,
): Promise<boolean> {
    const decoder = getCompiledTransactionMessageDecoder();
    const original = decoder.decode(originalMessageBytes);
    const returned = decoder.decode(returnedMessageBytes);
    if (original.version !== returned.version) {
        return false;
    }
    const originalLifetime = await getTransactionLifetimeConstraintFromCompiledTransactionMessage(original);
    if ('nonce' in originalLifetime) {
        if (!bytesEqual(originalMessageBytes, returnedMessageBytes)) return false;
        if (original.version !== 1) {
            validateManualCustomFee(policy.fee, normalizeManualFeeMessage(original).fees);
        }
        return true;
    }
    if (original.version === 1 || returned.version === 1) {
        return compareManualMessagesExactly(original, returned, true);
    }

    const normalizedOriginal = normalizeManualFeeMessage(original);
    if (normalizedOriginal.fees.price !== undefined) {
        if (!compareManualMessagesExactly(original, returned, true)) return false;
        validateManualCustomFee(policy.fee, normalizedOriginal.fees);
        return true;
    }
    const normalizedReturned = normalizeManualFeeMessage(returned);
    // The caller set no compute-unit price, so any price here is Fordefi's own
    // and is bounded by the absolute ceiling as well as any custom fee config.
    validateManualFeeCeiling(policy, normalizedReturned.fees);
    validateManualCustomFee(policy.fee, normalizedReturned.fees);
    const comparableReturned = {
        ...normalizedReturned.message,
        lifetimeToken: normalizedOriginal.message.lifetimeToken,
    } as LegacyOrV0CompiledMessage;
    return bytesEqual(encodeCompiledMessage(normalizedOriginal.message), encodeCompiledMessage(comparableReturned));
}

/**
 * Signs Fordefi API-request payloads for the `x-signature` header.
 *
 * Implementations receive the fully-formatted payload (`{path}|{timestamp}|{body}`)
 * and must return the exact base64 value Fordefi expects: base64 of the DER-encoded
 * ECDSA P-256 signature over `SHA-256(payload)`.
 *
 * The built-in PEM path (`privateKeyPem`) signs locally. To keep the request key in
 * a KMS/HSM, implement this interface and pass it as `requestSigner` (e.g. AWS KMS
 * `Sign` with `ECDSA_SHA_256` returns a DER signature — base64-encode it).
 */
export interface FordefiRequestSigner {
    /** Return the base64 `x-signature` value for `payload`. May be async. */
    signRequest(payload: string): Promise<string> | string;
}

/**
 * Built-in {@link FordefiRequestSigner} that signs locally with a PEM-encoded
 * ECDSA P-256 private key.
 */
class PemRequestSigner implements FordefiRequestSigner {
    private readonly privateKey: KeyObject;

    constructor(privateKeyPem: string) {
        this.privateKey = createPrivateKey(privateKeyPem);
    }

    signRequest(payload: string): string {
        const sign = createSign('SHA256').update(payload, 'utf8').end();
        return sign.sign(this.privateKey, 'base64');
    }
}

export interface FordefiSignerConfig {
    /** Fordefi API User bearer token */
    accessToken: string;
    /** Optional API base URL (default: https://api.fordefi.com) */
    apiBaseUrl?: string;
    /**
     * Solana chain identifier. When set, uses native Solana API types
     * (`solana_serialized_transaction_message` with `push_mode: 'auto'` for
     * transactions, `solana_message` for messages) instead of `black_box_signature`.
     */
    chain?: SolanaChainUniqueId;
    /** Solana fee configuration for native mode transactions. Only used when `chain` is set. */
    fee?: FordefiSolanaFee;
    /** Positive integer max polling attempts before timeout (default: 50) */
    maxPollAttempts?: number;
    /**
     * Ceiling, in lamports, on a priority fee Fordefi introduces itself during
     * native manual signing. Omitted applies
     * {@link DEFAULT_MAX_PRIORITY_FEE_LAMPORTS}, unless `fee` sets a custom
     * `priority_fee`, which governs instead. Never applies to a compute-unit
     * price the caller set, since those messages are compared byte-for-byte.
     */
    maxPriorityFeeLamports?: bigint | number;
    /** Non-negative integer polling interval in ms (default: 2000) */
    pollIntervalMs?: number;
    /**
     * PEM-encoded ECDSA P-256 private key for API request signing.
     * Provide exactly one of `privateKeyPem` or `requestSigner`.
     */
    privateKeyPem?: string;
    /** Solana public key of the vault (base58) */
    publicKey: string;
    /** Native Solana push mode. Omitted or `auto` preserves managed broadcasting. */
    pushMode?: 'auto';
    /** Optional delay in ms between concurrent signing requests (default: 0) */
    requestDelayMs?: number;
    /**
     * Custom API-request signer (e.g. a KMS/HSM-backed implementation).
     * Provide exactly one of `privateKeyPem` or `requestSigner`. When set,
     * `privateKeyPem` is ignored.
     */
    requestSigner?: FordefiRequestSigner;
    /**
     * Per-request HTTP timeout in ms applied to every signing-path network
     * call (submit POST and each poll GET). Default: 30000.
     */
    requestTimeoutMs?: number;
    /** Fordefi vault UUID */
    vaultId: string;
}

/** Configuration for Fordefi native signing without managed broadcasting. */
export type FordefiManualSignerConfig = Omit<FordefiSignerConfig, 'chain' | 'pushMode'> & {
    chain: SolanaChainUniqueId;
    pushMode: 'manual';
};

type AnyFordefiSignerConfig = FordefiManualSignerConfig | FordefiSignerConfig;

/**
 * Fordefi signer shape returned when `chain` enables native Solana mode.
 *
 * Native mode may replace the recent blockhash and fees before signing and
 * broadcasts with `push_mode: 'auto'`, so it must be used through Kit's
 * {@link TransactionSendingSigner} flow rather than as a partial signer.
 * Native instances expose no `signTransactions` — Kit classifies signers by
 * duck-typed method presence — but do sign messages.
 *
 * Native mode is not retry-safe: any failure after Fordefi accepts the
 * submission rejects with `BROADCAST_UNCONFIRMED` carrying
 * `context.providerTransactionId`; check that transaction with Fordefi before
 * retrying. A submission that fails without a usable response rejects with
 * `BROADCAST_UNCONFIRMED` and no `providerTransactionId`.
 *
 * Each native create carries an `x-idempotence-id` derived from the message
 * bytes, so replaying these exact bytes cannot create a second transaction; a
 * rebuilt transaction derives a different id and is broadcast again.
 */
export interface FordefiNativeSigner<TAddress extends string = string>
    extends SolanaSendingSigner<TAddress>, MessagePartialSigner<TAddress> {}

/**
 * Fordefi signer shape returned for native Solana `push_mode: 'manual'`.
 *
 * Requests are unsigned, so Fordefi may replace the recent blockhash and manage
 * priority-fee instructions. It signs without broadcasting; the caller applies
 * any remaining signatures and owns submission.
 */
export interface FordefiNativeManualSigner<TAddress extends string = string>
    extends SolanaModifyingSigner<TAddress>, MessagePartialSigner<TAddress> {}

/**
 * Create and initialize a Fordefi-backed signer.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when required config is missing or invalid.
 */
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiManualSignerConfig,
): Promise<FordefiNativeManualSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain: SolanaChainUniqueId },
): Promise<FordefiNativeSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: FordefiSignerConfig & { chain?: undefined },
): Promise<SolanaSigner<TAddress>>;
// Catch-all for a config whose mode is not statically known, as the
// `@solana/keychain` umbrella forwards. Concrete configs hit an overload above.
export async function createFordefiSigner<TAddress extends string = string>(
    config: AnyFordefiSignerConfig,
): Promise<FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress> | SolanaSigner<TAddress>>;
export async function createFordefiSigner<TAddress extends string = string>(
    config: AnyFordefiSignerConfig,
): Promise<FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress> | SolanaSigner<TAddress>> {
    // The instance's own properties expose the mode-appropriate signing
    // method, which the class type cannot express statically.
    return (await FordefiSigner.create(config)) as unknown as
        FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress> | SolanaSigner<TAddress>;
}

/**
 * Fordefi MPC signer using Fordefi's API.
 *
 * Transaction signing is async: submit via POST, poll GET until MPC signing completes.
 * API requests require ECDSA P-256 request-level signing.
 */
class FordefiSigner<TAddress extends string = string> implements MessagePartialSigner<TAddress> {
    readonly address: Address<TAddress>;
    declare modifyAndSignTransactions?: TransactionModifyingSigner<TAddress>['modifyAndSignTransactions'];
    declare signAndSendTransactions?: TransactionSendingSigner<TAddress>['signAndSendTransactions'];
    declare signTransactions?: TransactionPartialSigner<TAddress>['signTransactions'];
    private readonly accessToken: string;
    private readonly apiBaseUrl: string;
    private readonly chain?: SolanaChainUniqueId;
    private readonly fee?: FordefiSolanaFee;
    private readonly maxPollAttempts: number;
    /** `undefined` when the caller did not state a ceiling. */
    private readonly maxPriorityFeeLamports?: bigint;
    private readonly pollIntervalMs: number;
    private readonly pushMode: 'auto' | 'manual';
    private readonly requestSigner: FordefiRequestSigner;
    private readonly requestDelayMs: number;
    private readonly requestTimeoutMs: number;
    private readonly vaultId: string;

    private constructor(config: AnyFordefiSignerConfig, address: Address<TAddress>) {
        this.accessToken = config.accessToken;
        this.apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_BASE_URL);
        this.chain = config.chain;
        this.fee = config.fee;
        this.maxPollAttempts = config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS;
        this.maxPriorityFeeLamports =
            config.maxPriorityFeeLamports === undefined ? undefined : BigInt(config.maxPriorityFeeLamports);
        this.pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        this.pushMode = config.pushMode ?? 'auto';
        this.requestSigner = config.requestSigner ?? new PemRequestSigner(config.privateKeyPem ?? '');
        this.requestDelayMs = config.requestDelayMs ?? 0;
        this.requestTimeoutMs = config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
        this.vaultId = config.vaultId;
        this.address = address;

        // Kit classifies signers by duck-typed method presence, so each mode
        // exposes exactly the method it can honor as an own property. Native
        // manual mode returns a rewritten transaction, native auto mode
        // broadcasts it, and black-box mode signs the caller's exact bytes.
        if (this.chain && this.pushMode === 'manual') {
            this.modifyAndSignTransactions = this.modifyAndSignNativeTransactions.bind(this);
        } else if (this.chain) {
            this.signAndSendTransactions = this.signAndSendNativeTransactions.bind(this);
        } else {
            this.signTransactions = this.signBlackBoxTransactions.bind(this);
        }
    }

    /** Create a FordefiSigner with the provided configuration. */
    static async create<TAddress extends string = string>(
        config: FordefiManualSignerConfig,
    ): Promise<FordefiNativeManualSigner<TAddress> & FordefiSigner<TAddress>>;
    static async create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain: SolanaChainUniqueId },
    ): Promise<FordefiNativeSigner<TAddress> & FordefiSigner<TAddress>>;
    static async create<TAddress extends string = string>(
        config: FordefiSignerConfig & { chain?: undefined },
    ): Promise<FordefiSigner<TAddress> & SolanaSigner<TAddress>>;
    static async create<TAddress extends string = string>(
        config: AnyFordefiSignerConfig,
    ): Promise<
        FordefiSigner<TAddress> &
            (FordefiNativeManualSigner<TAddress> | FordefiNativeSigner<TAddress> | SolanaSigner<TAddress>)
    >;
    static async create<TAddress extends string = string>(
        config: AnyFordefiSignerConfig,
    ): Promise<FordefiSigner<TAddress>> {
        if (!config.accessToken) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'accessToken must not be empty',
            });
        }

        if (!config.vaultId) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'vaultId must not be empty',
            });
        }

        if (!config.publicKey) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'publicKey must not be empty',
            });
        }

        if (config.requestSigner && config.privateKeyPem) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'provide exactly one of privateKeyPem or requestSigner, not both',
            });
        }

        if (!config.requestSigner && !config.privateKeyPem) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'one of privateKeyPem or requestSigner must be provided',
            });
        }

        if (config.pushMode !== undefined && !PUSH_MODES.has(config.pushMode)) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: "pushMode must be 'auto' or 'manual'",
            });
        }

        if (config.pushMode === 'manual' && !config.chain) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: "pushMode 'manual' requires chain to enable Fordefi native Solana mode",
            });
        }

        FordefiSigner.validatePollingConfig(
            config.maxPollAttempts ?? DEFAULT_MAX_POLL_ATTEMPTS,
            config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
        );
        validateRequestDelayMs(config.requestDelayMs ?? 0);
        FordefiSigner.validateRequestTimeoutMs(config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);

        const apiBaseUrl = normalizeBaseUrl(config.apiBaseUrl ?? DEFAULT_BASE_URL);
        assertHttpsUrl(apiBaseUrl, 'apiBaseUrl');

        // Validate the PEM key can be parsed (only on the built-in PEM path).
        if (config.privateKeyPem) {
            try {
                createPrivateKey(config.privateKeyPem);
            } catch (error) {
                return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                    cause: error,
                    message: 'Failed to parse privateKeyPem as a valid private key',
                });
            }
        }

        try {
            assertIsAddress(config.publicKey);
        } catch (error) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                cause: error,
                message: 'Invalid Solana public key format',
            });
        }

        // Authoritative check: fetch the vault from Fordefi and verify that
        // `config.publicKey` actually belongs to `config.vaultId`. Without this
        // a valid-but-wrong address would pass configuration and later be
        // returned by resolveAddress(), creating a funds-routing risk.
        const verifiedAddress = await FordefiSigner.fetchAndVerifyVaultAddress({
            accessToken: config.accessToken,
            apiBaseUrl,
            expectedPublicKey: config.publicKey,
            vaultId: config.vaultId,
        });

        return new FordefiSigner<TAddress>(config, verifiedAddress as Address<TAddress>);
    }

    /**
     * Fetch the vault from Fordefi and assert the returned Solana address
     * matches `expectedPublicKey`.
     */
    private static async fetchAndVerifyVaultAddress({
        accessToken,
        apiBaseUrl,
        expectedPublicKey,
        vaultId,
    }: {
        accessToken: string;
        apiBaseUrl: string;
        expectedPublicKey: string;
        vaultId: string;
    }): Promise<Address> {
        const url = `${apiBaseUrl}/api/v1/vaults/${vaultId}`;
        const vault = await fetchSignerJson<FordefiVaultResponse>({
            init: {
                headers: { Authorization: `Bearer ${accessToken}` },
                method: 'GET',
            },
            providerName: 'Fordefi',
            timeoutMs: 10_000,
            url,
        });

        // Regular Fordefi Solana vaults expose `address` directly; black_box vaults
        // only provide `public_key_compressed` (base64-encoded Ed25519 key).
        let remoteAddress = vault.address;
        if (!remoteAddress && vault.public_key_compressed) {
            try {
                base64Encoder ||= getBase64Encoder();
                base58Decoder ||= getBase58Decoder();
                const keyBytes = base64Encoder.encode(vault.public_key_compressed);
                remoteAddress = base58Decoder.decode(keyBytes);
            } catch (error) {
                return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                    cause: error,
                    message: 'Failed to derive Solana address from vault public_key_compressed',
                });
            }
        }
        if (!remoteAddress) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message:
                    'Fordefi vault response included neither `address` nor `public_key_compressed`; cannot verify publicKey ownership',
            });
        }

        if (remoteAddress !== expectedPublicKey) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: `Configured publicKey does not match Fordefi vault ${vaultId}: expected ${remoteAddress}`,
            });
        }

        try {
            assertIsAddress(remoteAddress);
        } catch (error) {
            return throwSignerError(SignerErrorCode.INVALID_PUBLIC_KEY, {
                cause: error,
                message: 'Fordefi vault returned an invalid Solana address',
            });
        }

        return remoteAddress;
    }

    /**
     * Lightweight readiness probe.
     *
     * Checks that the bearer token and vault are reachable (GET does not
     * require `x-signature`), then exercises the local P-256 signing path
     * to catch a malformed `privateKeyPem` early. Note: a passing local
     * sign does not guarantee the Fordefi server recognises the
     * corresponding public key — that is only proven on the first real
     * POST signing call.
     */
    async isAvailable(): Promise<boolean> {
        try {
            await this.request<FordefiVaultResponse>('GET', `/api/v1/vaults/${this.vaultId}`, undefined, 5_000);
        } catch {
            return false;
        }

        try {
            await this.signRequest('/api/v1/vaults', Date.now(), '');
        } catch {
            return false;
        }

        return true;
    }

    async signMessages(
        messages: readonly SignableMessage[],
        config?: MessagePartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            messages,
            async message => {
                const signatureBytes = await this.signMessage(message.content, config?.abortSignal);
                await assertSignatureValid({
                    data: message.content,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return createSignatureDictionary({
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Partial-signer path for black-box mode; attached as an own property only
     * when `chain` is unset.
     */
    private async signBlackBoxTransactions(
        transactions: readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[],
        config?: TransactionPartialSignerConfig,
    ): Promise<readonly SignatureDictionary[]> {
        return await signBatchStaggered(
            transactions,
            async transaction => {
                const { sigDict, verificationData } = await this.signBlackBoxTransaction(
                    transaction.messageBytes,
                    config?.abortSignal,
                );
                const signatureBytes = Object.values(sigDict)[0];
                if (!signatureBytes) {
                    return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        address: this.address,
                        message: 'No signature bytes found in extracted signature dictionary',
                    });
                }
                await assertSignatureValid({
                    data: verificationData,
                    signature: signatureBytes,
                    signerAddress: this.address,
                });
                return sigDict;
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Sign an unchanged Solana transaction message through Fordefi's black-box API.
     *
     * The raw Ed25519 signature is valid regardless of this signer's account
     * index, so this path supports multi-signature transactions where Fordefi
     * is not the fee payer.
     */
    private async signBlackBoxTransaction(
        messageBytes: ArrayLike<number>,
        abortSignal?: AbortSignal,
    ): Promise<{ sigDict: SignatureDictionary; verificationData: Uint8Array }> {
        const bytes = messageBytes instanceof Uint8Array ? messageBytes : new Uint8Array(Array.from(messageBytes));
        base64Decoder ||= getBase64Decoder();
        const base64Data = base64Decoder.decode(bytes);

        const txId = await this.submitBlackBoxSignature(base64Data, abortSignal);
        const result = await this.pollForResult(txId, { pushable: false }, abortSignal);
        const sigBase64 = this.extractSignatureData(result);
        let sigBytes: Uint8Array;
        try {
            base64Encoder ||= getBase64Encoder();
            sigBytes = new Uint8Array(base64Encoder.encode(sigBase64));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi signature base64',
            });
        }
        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected ${ED25519_SIGNATURE_LENGTH}-byte Ed25519 signature, got ${sigBytes.length}`,
            });
        }
        return {
            sigDict: createSignatureDictionary({ signature: sigBytes as SignatureBytes, signerAddress: this.address }),
            verificationData: bytes,
        };
    }

    /**
     * Native manual path for Kit's TransactionModifyingSigner contract. Fordefi
     * signs first so it may replace the lifetime token and manage priority-fee
     * instructions; remaining signers then sign the validated result.
     */
    private async modifyAndSignNativeTransactions(
        transactions: readonly (Transaction | (Transaction & TransactionWithLifetime))[],
        config?: TransactionModifyingSignerConfig,
    ): Promise<readonly (Transaction & TransactionWithinSizeLimit & TransactionWithLifetime)[]> {
        if (!this.chain || this.pushMode !== 'manual') {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                address: this.address,
                message: "modifyAndSignTransactions() requires chain and pushMode 'manual'",
            });
        }

        config?.abortSignal?.throwIfAborted();
        return await signBatchStaggered(
            transactions,
            async transaction => {
                config?.abortSignal?.throwIfAborted();
                this.assertNativeManualTransactionSupported(transaction);

                base64Decoder ||= getBase64Decoder();
                const base64Data = base64Decoder.decode(transaction.messageBytes);
                const txId = await this.submitSolanaTransaction(base64Data, 'manual', config?.abortSignal);
                return await this.finishNativeManualSigning(txId, transaction, config);
            },
            this.requestDelayMs,
        );
    }

    /** Decode and validate the signed transaction returned by manual mode. */
    private async finishNativeManualSigning(
        txId: string,
        originalTransaction: Transaction | (Transaction & TransactionWithLifetime),
        config?: TransactionModifyingSignerConfig,
    ): Promise<Transaction & TransactionWithinSizeLimit & TransactionWithLifetime> {
        const result = await this.pollForResult(txId, { pushable: false }, config?.abortSignal);
        if (!result.raw_transaction) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Fordefi manual solana_transaction response missing raw_transaction',
            });
        }

        let decodedTransaction: Transaction;
        try {
            base64Encoder ||= getBase64Encoder();
            decodedTransaction = getTransactionDecoder().decode(base64Encoder.encode(result.raw_transaction));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi manual raw_transaction',
            });
        }

        const originalSignerAddresses = Object.keys(originalTransaction.signatures);
        const returnedSignerAddresses = Object.keys(decodedTransaction.signatures);
        if (
            originalSignerAddresses.length !== returnedSignerAddresses.length ||
            originalSignerAddresses.some((address, index) => address !== returnedSignerAddresses[index])
        ) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi manual signing changed the transaction required-signer set',
            });
        }

        let messageContentMatches: boolean;
        try {
            messageContentMatches = await manualMessagesMatchFordefiMutationPolicy(
                new Uint8Array(originalTransaction.messageBytes),
                new Uint8Array(decodedTransaction.messageBytes),
                { fee: this.fee, maxPriorityFeeLamports: this.maxPriorityFeeLamports },
            );
        } catch (error) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Fordefi returned an invalid manual transaction mutation',
            });
        }
        if (!messageContentMatches) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message:
                    'Fordefi manual signing changed transaction content outside the recent blockhash and priority fee',
            });
        }

        const signerSignature = decodedTransaction.signatures[this.address];
        if (!signerSignature) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi manual wire transaction did not contain the configured vault signature',
            });
        }
        if (
            Object.entries(decodedTransaction.signatures).some(
                ([address, signature]) => address !== this.address && signature !== null,
            )
        ) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi manual signing unexpectedly populated a downstream signer slot',
            });
        }

        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature: signerSignature,
            signerAddress: this.address,
        });

        const lifetimeConstraint = await this.getReturnedLifetimeConstraint(originalTransaction, decodedTransaction);
        const modifiedTransaction = Object.freeze({
            ...decodedTransaction,
            lifetimeConstraint,
            signatures: Object.freeze(decodedTransaction.signatures),
        });

        try {
            assertIsTransactionWithinSizeLimit(modifiedTransaction);
        } catch (error) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Fordefi manual wire transaction exceeds the Solana transaction size limit',
            });
        }

        config?.abortSignal?.throwIfAborted();
        return modifiedTransaction;
    }

    /**
     * Recover the returned transaction lifetime from its compiled message.
     * Kit uses U64_MAX when a blockhash's exact last-valid height is unknown.
     */
    private async getReturnedLifetimeConstraint(
        originalTransaction: Transaction | (Transaction & TransactionWithLifetime),
        returnedTransaction: Transaction,
    ): Promise<TransactionWithLifetime['lifetimeConstraint']> {
        let returnedLifetime: TransactionWithLifetime['lifetimeConstraint'];
        try {
            const compiledMessage = getCompiledTransactionMessageDecoder().decode(returnedTransaction.messageBytes);
            returnedLifetime = await getTransactionLifetimeConstraintFromCompiledTransactionMessage(compiledMessage);
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to recover the lifetime from Fordefi manual raw_transaction',
            });
        }

        if ('lifetimeConstraint' in originalTransaction) {
            const originalLifetime = originalTransaction.lifetimeConstraint;
            const retainedOriginalLifetime =
                ('blockhash' in originalLifetime &&
                    'blockhash' in returnedLifetime &&
                    originalLifetime.blockhash === returnedLifetime.blockhash) ||
                ('nonce' in originalLifetime &&
                    'nonce' in returnedLifetime &&
                    originalLifetime.nonce === returnedLifetime.nonce);
            if (retainedOriginalLifetime) {
                return originalLifetime;
            }
        }

        return returnedLifetime;
    }

    /**
     * Native Solana transaction path for Kit's TransactionSendingSigner contract.
     *
     * Fordefi may replace the message lifetime and fees, then broadcasts the
     * returned transaction itself. The result is therefore the on-chain
     * transaction identifier (the first wire signature), not a signature
     * dictionary to be applied to the caller's original message.
     */
    private async signAndSendNativeTransactions(
        transactions: readonly (Transaction | (Transaction & TransactionWithLifetime))[],
        config?: TransactionSendingSignerConfig,
    ): Promise<readonly SignatureBytes[]> {
        if (!this.chain) {
            return throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                address: this.address,
                message: 'signAndSendTransactions() requires chain to enable Fordefi native Solana mode',
            });
        }

        config?.abortSignal?.throwIfAborted();
        return await signBatchStaggered(
            transactions,
            async transaction => {
                config?.abortSignal?.throwIfAborted();
                this.assertNativeAutoTransactionSupported(transaction);

                base64Decoder ||= getBase64Decoder();
                const base64Data = base64Decoder.decode(transaction.messageBytes);
                let txId: string;
                try {
                    txId = await this.submitSolanaTransaction(base64Data, 'auto', config?.abortSignal);
                } catch (error) {
                    if (!providerMayHaveAccepted(error)) {
                        throw error;
                    }
                    // Fordefi may be broadcasting a transaction whose id never reached us.
                    const status = providerStatus(error);
                    return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        cause: error,
                        message: 'Fordefi may have accepted the transaction, but no transaction id was returned',
                        ...(status === undefined ? {} : { status }),
                    });
                }
                // Once the submit is accepted Fordefi is already broadcasting
                // (push_mode 'auto'), so any later failure leaves an on-chain
                // outcome this client cannot rule out. Report those as
                // BROADCAST_UNCONFIRMED carrying the Fordefi transaction id
                // instead of a generic error a caller might blindly retry into
                // a duplicate spend.
                try {
                    return await this.finishNativeBroadcast(txId, config);
                } catch (error) {
                    return throwSignerError(SignerErrorCode.BROADCAST_UNCONFIRMED, {
                        cause: error,
                        message: `Fordefi may have executed the transaction, but the outcome could not be confirmed (provider transaction id: ${txId})`,
                        providerTransactionId: txId,
                    });
                }
            },
            this.requestDelayMs,
            config?.abortSignal,
        );
    }

    /**
     * Poll a submitted native transaction to completion and extract and verify
     * the vault's signature from the returned wire bytes.
     */
    private async finishNativeBroadcast(
        txId: string,
        config?: TransactionSendingSignerConfig,
    ): Promise<SignatureBytes> {
        const result = await this.pollForResult(txId, { pushable: true }, config?.abortSignal);
        if (!result.raw_transaction) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Fordefi solana_transaction response missing raw_transaction',
            });
        }

        const signedWireTx = result.raw_transaction as Base64EncodedWireTransaction;
        base64Encoder ||= getBase64Encoder();
        const decodedTransaction = getTransactionDecoder().decode(base64Encoder.encode(signedWireTx));

        const signerSignature = decodedTransaction.signatures[this.address];
        if (!signerSignature) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi wire transaction did not contain the configured vault signature',
            });
        }

        // Kit resolves the fee payer's signature, whichever slot the version puts it in.
        let transactionSignature: SignatureBytes;
        try {
            base58Encoder ||= getBase58Encoder();
            transactionSignature = base58Encoder.encode(
                getSignatureFromTransaction(decodedTransaction),
            ) as SignatureBytes;
        } catch (error) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                cause: error,
                message: 'Fordefi wire transaction carries no fee-payer signature to identify the broadcast by',
            });
        }

        await assertSignatureValid({
            data: decodedTransaction.messageBytes,
            signature: signerSignature,
            signerAddress: this.address,
        });
        config?.abortSignal?.throwIfAborted();
        return transactionSignature;
    }

    /**
     * The current request schema sends only message bytes. Supporting native
     * multi-signer auto-broadcast would also require forwarding all other
     * partial signatures via Fordefi's `details.signatures` field.
     */
    private assertNativeAutoTransactionSupported(transaction: Transaction): void {
        const requiredSignerAddresses = Object.keys(transaction.signatures);
        if (requiredSignerAddresses.length !== 1 || requiredSignerAddresses[0] !== this.address) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message:
                    'Fordefi native auto-broadcast currently supports only transactions whose sole required signer is the configured vault',
            });
        }
    }

    /** Manual native signing must run first, with the Fordefi vault as fee payer. */
    private assertNativeManualTransactionSupported(transaction: Transaction): void {
        const requiredSignerAddresses = Object.keys(transaction.signatures);
        if (requiredSignerAddresses[0] !== this.address) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi native manual signing requires the configured vault to be the transaction fee payer',
            });
        }
        if (Object.values(transaction.signatures).some(signature => signature !== null)) {
            throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                address: this.address,
                message: 'Fordefi native manual signing must run before any transaction signatures are applied',
            });
        }
    }

    /**
     * POST a transaction request to Fordefi and return the transaction ID.
     * Shared by all signing modes (black_box, solana_transaction, solana_message).
     */
    private async submitTransaction(
        requestBody: FordefiBlackBoxSignatureRequest | FordefiSolanaMessageRequest | FordefiSolanaTransactionRequest,
        idempotenceId?: string,
        abortSignal?: AbortSignal,
    ): Promise<string> {
        const apiPath = '/api/v1/transactions';
        const createResponse = await this.request<FordefiCreateTransactionResponse>(
            'POST',
            apiPath,
            JSON.stringify(requestBody),
            this.requestTimeoutMs,
            idempotenceId,
            abortSignal,
        );
        return createResponse.id;
    }

    /**
     * Submit a black_box_signature request for raw EdDSA signing.
     */
    private async submitBlackBoxSignature(base64Data: string, abortSignal?: AbortSignal): Promise<string> {
        const requestBody: FordefiBlackBoxSignatureRequest = {
            details: {
                format: 'hash_binary',
                hash_binary: base64Data,
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'black_box_signature',
            vault_id: this.vaultId,
        };
        return await this.submitTransaction(requestBody, undefined, abortSignal);
    }

    /**
     * Submit a native Solana serialized transaction message for signing.
     */
    private async submitSolanaTransaction(
        base64Data: string,
        pushMode: 'auto' | 'manual' = 'auto',
        abortSignal?: AbortSignal,
    ): Promise<string> {
        const requestBody: FordefiSolanaTransactionRequest = {
            details: {
                chain: this.chain!,
                data: base64Data,
                ...(this.fee ? { fee: this.fee } : {}),
                push_mode: pushMode,
                type: 'solana_serialized_transaction_message',
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'solana_transaction',
            vault_id: this.vaultId,
        };
        base64Encoder ||= getBase64Encoder();
        const messageBytes = base64Encoder.encode(base64Data);
        let idempotencyInput = messageBytes;
        if (pushMode === 'manual') {
            utf8Encoder ||= getUtf8Encoder();
            const namespace = utf8Encoder.encode(`fordefi:solana:manual:${this.chain}:${this.vaultId}:`);
            const namespacedInput = new Uint8Array(namespace.length + messageBytes.length);
            namespacedInput.set(namespace);
            namespacedInput.set(messageBytes, namespace.length);
            idempotencyInput = namespacedInput;
        }
        return await this.submitTransaction(
            requestBody,
            await idempotencyKeyFromMessage(idempotencyInput),
            abortSignal,
        );
    }

    /**
     * Submit a native Solana personal message for signing.
     */
    private async submitSolanaMessage(base64Data: string, abortSignal?: AbortSignal): Promise<string> {
        const requestBody: FordefiSolanaMessageRequest = {
            details: {
                chain: this.chain!,
                raw_data: base64Data,
                type: 'personal_message_type',
            },
            sign_mode: 'auto',
            signer_type: 'api_signer',
            type: 'solana_message',
            vault_id: this.vaultId,
        };
        return await this.submitTransaction(requestBody, undefined, abortSignal);
    }

    /**
     * Sign a Solana personal message via Fordefi MPC.
     * Submits the message, polls for completion, and returns the raw 64-byte Ed25519 signature.
     */
    private async signMessage(messageBytes: Uint8Array, abortSignal?: AbortSignal): Promise<SignatureBytes> {
        base64Decoder ||= getBase64Decoder();
        const base64Data = base64Decoder.decode(messageBytes);

        const txId = this.chain
            ? await this.submitSolanaMessage(base64Data, abortSignal)
            : await this.submitBlackBoxSignature(base64Data, abortSignal);
        const result = await this.pollForResult(txId, { pushable: false }, abortSignal);
        const sigBase64 = this.extractSignatureData(result);

        let sigBytes: Uint8Array;
        try {
            base64Encoder ||= getBase64Encoder();
            sigBytes = new Uint8Array(base64Encoder.encode(sigBase64));
        } catch (error) {
            return throwSignerError(SignerErrorCode.PARSING_ERROR, {
                cause: error,
                message: 'Failed to decode Fordefi signature base64',
            });
        }

        if (sigBytes.length !== ED25519_SIGNATURE_LENGTH) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: `Expected ${ED25519_SIGNATURE_LENGTH}-byte Ed25519 signature, got ${sigBytes.length}`,
            });
        }

        return sigBytes as SignatureBytes;
    }

    /**
     * Poll until the transaction reaches a terminal state and return the full response.
     *
     * @param pushable - When `true`, treats pushable success state
     *   `completed` as terminal. When `false`, uses non-pushable states
     *   (`signed`, `completed`).
     */
    private async pollForResult(
        txId: string,
        { pushable }: { pushable: boolean },
        abortSignal?: AbortSignal,
    ): Promise<FordefiTransactionStatusResponse> {
        const successStates = pushable ? PUSHABLE_SUCCESS_STATES : NON_PUSHABLE_SUCCESS_STATES;

        for (let attempt = 0; attempt < this.maxPollAttempts; attempt++) {
            const txData = await this.request<FordefiTransactionStatusResponse>(
                'GET',
                `/api/v1/transactions/${txId}`,
                undefined,
                undefined,
                undefined,
                abortSignal,
            );

            if (successStates.has(txData.state)) {
                return txData;
            }

            if (FAILURE_STATES.has(txData.state)) {
                return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    message: `Transaction ${txId} reached terminal state: ${txData.state}`,
                });
            }

            if (attempt + 1 < this.maxPollAttempts) {
                await abortableDelay(this.pollIntervalMs, abortSignal);
            }
        }

        return throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Polling timeout after ${this.maxPollAttempts} attempts`,
        });
    }

    /**
     * Extract the base64-encoded signature from a poll result.
     */
    private extractSignatureData(result: FordefiTransactionStatusResponse): string {
        const sigData = result.signatures?.[0]?.data;
        if (!sigData) {
            return throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                message: 'Transaction signed but no signatures in response',
            });
        }
        return sigData;
    }

    /**
     * Sign an API request payload via the configured {@link FordefiRequestSigner}.
     * Payload format: `{path}|{timestamp}|{body}`
     */
    private async signRequest(path: string, timestamp: number, body: string): Promise<string> {
        const payload = `${path}|${timestamp}|${body}`;
        return await this.requestSigner.signRequest(payload);
    }

    /**
     * Make an authenticated request to the Fordefi API.
     */
    private async request<T>(
        method: 'GET' | 'POST',
        apiPath: string,
        body?: string,
        timeoutMs = this.requestTimeoutMs,
        idempotenceId?: string,
        abortSignal?: AbortSignal,
    ): Promise<T> {
        const headers: Record<string, string> = {
            Authorization: `Bearer ${this.accessToken}`,
        };
        if (body !== undefined) {
            const timestamp = Date.now();
            headers['Content-Type'] = 'application/json';
            headers['x-signature'] = await this.signRequest(apiPath, timestamp, body);
            headers['x-timestamp'] = timestamp.toString();
        }
        if (idempotenceId !== undefined) {
            headers['x-idempotence-id'] = idempotenceId;
        }

        return await fetchSignerJson<T>({
            abortSignal,
            init: { body, headers, method },
            providerName: 'Fordefi',
            timeoutMs,
            url: `${this.apiBaseUrl}${apiPath}`,
        });
    }

    private static validatePollingConfig(maxPollAttempts: number, pollIntervalMs: number): void {
        if (!Number.isSafeInteger(maxPollAttempts) || maxPollAttempts < 1) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'maxPollAttempts must be a positive integer',
            });
        }
        if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'pollIntervalMs must be a non-negative integer',
            });
        }
    }

    private static validateRequestTimeoutMs(requestTimeoutMs: number): void {
        if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
            throwSignerError(SignerErrorCode.CONFIG_ERROR, {
                message: 'requestTimeoutMs must be a positive finite number',
            });
        }
    }
}
