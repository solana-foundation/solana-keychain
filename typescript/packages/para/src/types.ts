/**
 * Para API error response
 */
export interface ParaErrorResponse {
    message: string;
}

/**
 * Para wallet response from GET /v1/wallets/:walletId
 */
export interface ParaWalletResponse {
    address: string;
    id: string;
    publicKey: string;
    status: string;
    type: string;
}

/**
 * Para sign-raw request body
 */
export interface ParaSignRawRequest {
    data: string;
    encoding: 'hex';
}

/**
 * Para sign-raw response
 */
export interface ParaSignRawResponse {
    signature: string;
}
