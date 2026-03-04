/**
 * Configuration for creating a DfnsSigner
 */
export interface DfnsSignerConfig {
    /** API base URL (default: "https://api.dfns.io") */
    apiBaseUrl?: string;

    /** Service account token or personal access token */
    authToken: string;

    /** Credential ID for user action signing */
    credId: string;

    /** Private key in PEM format for signing user action challenges (Ed25519, P256, or RSA) */
    privateKeyPem: string;

    /** Optional delay in ms between concurrent signing requests to avoid rate limits (default: 0) */
    requestDelayMs?: number;

    /** Dfns wallet ID */
    walletId: string;
}

/**
 * Dfns wallet response
 */
export interface GetWalletResponse {
    id: string;
    signingKey: {
        curve: string;
        id: string;
        publicKey: string;
        scheme: string;
    };
    status: string;
}

/**
 * Message signature request body for Dfns Keys API
 */
export interface GenerateMessageSignatureRequest {
    kind: 'Message';
    message: string;
}

/**
 * Transaction signature request body for Dfns Keys API
 */
export interface GenerateTransactionSignatureRequest {
    blockchainKind: string;
    kind: 'Transaction';
    transaction: string;
}

export type GenerateSignatureRequest = GenerateMessageSignatureRequest | GenerateTransactionSignatureRequest;

/**
 * Signature response from Dfns Keys API
 */
export interface GenerateSignatureResponse {
    id: string;
    signature?: SignatureComponents;
    signedData?: string;
    status: string;
}

export interface SignatureComponents {
    r: string;
    s: string;
}

/**
 * User action challenge init request
 */
export interface UserActionInitRequest {
    userActionHttpMethod: string;
    userActionHttpPath: string;
    userActionPayload: string;
    userActionServerKind: string;
}

/**
 * User action challenge init response
 */
export interface UserActionInitResponse {
    allowCredentials: {
        key: Array<{ id: string }>;
    };
    challenge: string;
    challengeIdentifier: string;
}

/**
 * User action sign request
 */
export interface UserActionSignRequest {
    challengeIdentifier: string;
    firstFactor: {
        credentialAssertion: {
            clientData: string;
            credId: string;
            signature: string;
        };
        kind: string;
    };
}

/**
 * User action sign response
 */
export interface UserActionResponse {
    userAction: string;
}
