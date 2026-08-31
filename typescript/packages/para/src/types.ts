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

export interface ParaSignRawRequest {
    data: string;
    encoding: 'hex';
}

export interface ParaSignRawResponse {
    signature: string;
}
