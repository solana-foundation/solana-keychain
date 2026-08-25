export type SolanaChainUniqueId = 'solana_devnet' | 'solana_mainnet';

export interface FordefiErrorResponse {
    detail?: string;
    error_type?: string;
    message?: string;
    request_id?: string;
    title?: string;
}

/**
 * Request body for POST /api/v1/transactions (black_box vault).
 *
 * Black box vaults sign raw bytes via EdDSA and return a pure Ed25519 signature
 * without any chain-specific semantics.
 */
export interface FordefiBlackBoxSignatureRequest {
    details: {
        format: 'hash_binary';
        hash_binary: string;
    };
    sign_mode: 'auto';
    signer_type: 'api_signer';
    type: 'black_box_signature';
    vault_id: string;
}

/**
 * Fee configuration for a native Solana transaction request, mapping onto the
 * Compute Budget instructions Fordefi places in the message.
 *
 * The `custom` amounts are decimal integer strings because both are u64 values
 * that a JSON number cannot represent exactly.
 */
export type FordefiSolanaFee =
    | {
          /**
           * Total priority fee in lamports — the compute-unit price multiplied
           * by the compute-unit limit, divided by 1e6 and rounded up. Bounds
           * the fee Fordefi may introduce; excludes the 5000-lamport-per-
           * signature base fee.
           */
          priority_fee?: string;
          type: 'custom';
          /** Compute-unit price in micro-lamports per compute unit (`SetComputeUnitPrice`). */
          unit_price?: string;
      }
    | { priority_level: 'high' | 'low' | 'medium'; type: 'priority' };

/**
 * Request body for native Solana transaction signing via
 * `solana_serialized_transaction_message`.
 *
 * Fordefi signs the serialized transaction message and either pushes it
 * on-chain (`auto`) or returns it for caller-managed broadcasting (`manual`).
 */
export interface FordefiSolanaTransactionRequest {
    details: {
        chain: SolanaChainUniqueId;
        data: string;
        fee?: FordefiSolanaFee;
        push_mode: 'auto' | 'manual';
        type: 'solana_serialized_transaction_message';
    };
    sign_mode: 'auto';
    signer_type: 'api_signer';
    type: 'solana_transaction';
    vault_id: string;
}

/**
 * Request body for native Solana message signing via `solana_message`.
 *
 * Fordefi signs a personal message (non-pushable).
 */
export interface FordefiSolanaMessageRequest {
    details: {
        chain: SolanaChainUniqueId;
        raw_data: string;
        type: 'personal_message_type';
    };
    sign_mode: 'auto';
    signer_type: 'api_signer';
    type: 'solana_message';
    vault_id: string;
}

/**
 * Response from POST /api/v1/transactions
 */
export interface FordefiCreateTransactionResponse {
    id: string;
}

export interface FordefiSignatureEntry {
    data: string;
}

/**
 * Response from GET /api/v1/transactions/{id} (polling)
 */
export interface FordefiTransactionStatusResponse {
    /** Base64-encoded signed wire transaction (present on solana_transaction responses). */
    raw_transaction?: string;
    signatures?: FordefiSignatureEntry[];
    state: string;
}

/**
 * Response from GET /api/v1/vaults/{id}.
 *
 * Used both for availability checks and for authoritative verification
 * that a configured Solana `publicKey` actually belongs to the vault.
 */
export interface FordefiVaultResponse {
    /** Solana base58 address bound to the vault (present on chain-specific vaults). */
    address?: string;
    id: string;
    /** Base64-encoded compressed public key (present on black_box vaults). */
    public_key_compressed?: string;
    /** Vault type — "black_box" vaults lack an `address` and use `public_key_compressed` instead. */
    type?: string;
}
