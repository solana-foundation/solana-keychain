export type VaultSignatureBase64 = string & { readonly __brand: unique symbol };

export type VaultPayloadBase64 = string & { readonly __brand: unique symbol };

export interface VaultSignRequest {
    /**
     * Hash algorithm to use (optional, defaults to sha2-256)
     * Not typically needed for ED25519 keys as they handle hashing internally
     */
    hash_algorithm?: 'sha2-256' | 'sha2-384' | 'sha2-512';

    /**
     * The base64 encoded data to sign
     */
    input: VaultPayloadBase64;

    /**
     * Whether to hash the input before signing (optional, defaults to false)
     * Not typically sent as Vault defaults to false
     */
    prehashed?: boolean;

    /**
     * Signature algorithm (optional)
     * Not typically sent as the key type determines the algorithm
     */
    signature_algorithm?: 'ed25519' | 'rsa-2048' | 'rsa-3072' | 'rsa-4096';
}

export interface VaultSignResponse {
    /**
     * Optional authentication information
     */
    auth?: unknown;

    data: {
        /**
         * Optional key version used for signing
         */
        key_version?: number;

        /**
         * The signature in the format "vault:v1:signature_base64"
         */
        signature: string;
    };

    /**
     * Optional warnings from Vault
     */
    warnings?: string[];
}

/**
 * Request to read key metadata from Vault transit engine
 * No request body needed for key metadata read
 */
export type VaultKeyReadRequest = Record<string, never>;

export interface VaultKeyReadResponse {
    data: {
        /**
         * Key creation time
         */
        creation_time: string;

        /**
         * Whether the key is deletable
         */
        deletion_allowed: boolean;

        /**
         * Whether the key can be exported
         */
        exportable: boolean;

        /**
         * Current version of the key
         */
        latest_version: number;

        /**
         * Minimum version for decryption
         */
        min_decryption_version?: number;

        /**
         * Minimum version for encryption
         */
        min_encryption_version?: number;

        /**
         * Whether the key can be used for encryption
         */
        supports_encryption: boolean;

        /**
         * Whether the key can be used for signing
         */
        supports_signing: boolean;

        /**
         * Key type (e.g., "ed25519", "rsa-2048", etc.)
         */
        type: string;
    };
}

export interface VaultErrorResponse {
    errors: string[];
}
