/**
 * Turnkey API request and response types
 * Based on Turnkey's API v1 specification
 */

/**
 * Sign request parameters for ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2
 */
export interface SignParameters {
    /** Payload encoding format */
    encoding: 'PAYLOAD_ENCODING_HEXADECIMAL';
    /** Hash function to use (NOT_APPLICABLE for pre-hashed data) */
    hashFunction: 'HASH_FUNCTION_NOT_APPLICABLE';
    /** Hex-encoded payload to sign */
    payload: string;
    /** Turnkey private key ID to sign with */
    signWith: string;
}

export interface SignRequest {
    /** Organization ID */
    organizationId: string;
    /** Request parameters */
    parameters: SignParameters;
    /** Timestamp in milliseconds */
    timestampMs: string;
    /** Activity type */
    type: 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2';
}

/**
 * Sign response with r,s signature components
 */
export interface SignRawPayloadResult {
    /** Hex-encoded r component of signature */
    r: string;
    /** Hex-encoded s component of signature */
    s: string;
}

/**
 * Sign transaction request parameters for ACTIVITY_TYPE_SIGN_TRANSACTION_V2
 */
export interface SignTransactionParameters {
    /** Turnkey private key ID to sign with */
    signWith: string;
    /** Transaction type */
    type: 'TRANSACTION_TYPE_SOLANA';
    /** Raw unsigned transaction to be signed (hex-encoded) */
    unsignedTransaction: string;
}

export interface SignTransactionRequest {
    /** Organization ID */
    organizationId: string;
    /** Request parameters */
    parameters: SignTransactionParameters;
    /** Timestamp in milliseconds */
    timestampMs: string;
    /** Activity type */
    type: 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2';
}

/**
 * Sign transaction result
 */
export interface SignTransactionResult {
    /** Hex-encoded signed transaction */
    signedTransaction: string;
}

export interface ActivityResult {
    /** Sign result containing signature components */
    signRawPayloadResult?: SignRawPayloadResult;
    /** Sign transaction result containing signed transaction */
    signTransactionResult?: SignTransactionResult;
}

/**
 * Activity response from Turnkey
 */
export interface Activity {
    /** Activity result */
    result?: ActivityResult;
    /** Activity status */
    status: string;
}

export interface ActivityResponse {
    /** Activity details */
    activity: Activity;
}

/**
 * WhoAmI request for health check
 */
export interface WhoAmIRequest {
    /** Organization ID */
    organizationId: string;
}

export interface WhoAmIResponse {
    /** Organization ID */
    organizationId: string;
    /** Organization name */
    organizationName: string;
    /** User information */
    userId?: string;
    /** User Name */
    username?: string;
}
