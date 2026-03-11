import * as crypto from 'node:crypto';

import { base64UrlEncode, SignerErrorCode, throwSignerError } from '@solana/keychain-core';

import type { UserActionInitResponse, UserActionResponse } from './types.js';

/**
 * Perform the Dfns User Action Signing flow. For more details, see https://docs.dfns.co/api-reference/auth/signing-flows#asymetric-keys-signing-flow
 *
 * @returns The `userAction` token to include as `x-dfns-useraction` header.
 */
export async function signUserAction(
    apiBaseUrl: string,
    authToken: string,
    credId: string,
    privateKeyPem: string,
    httpMethod: string,
    httpPath: string,
    body: string,
): Promise<string> {
    // Request a challenge
    const initUrl = `${apiBaseUrl}/auth/action/init`;
    let initResponse: Response;
    try {
        initResponse = await fetch(initUrl, {
            body: JSON.stringify({
                userActionHttpMethod: httpMethod,
                userActionHttpPath: httpPath,
                userActionPayload: body,
                userActionServerKind: 'Api',
            }),
            headers: {
                Authorization: `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
            method: 'POST',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Dfns network request failed',
            url: initUrl,
        });
    }

    if (!initResponse.ok) {
        const errorText = await initResponse.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Dfns auth/action/init failed: ${initResponse.status}`,
            response: errorText,
            status: initResponse.status,
        });
    }

    let challenge: UserActionInitResponse;
    try {
        challenge = (await initResponse.json()) as UserActionInitResponse;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Dfns auth challenge response',
        });
    }

    // Verify credential is allowed
    const allowed = challenge.allowCredentials.key.some(c => c.id === credId);
    if (!allowed) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Credential ${credId} not in allowed credentials`,
        });
    }

    // Sign the challenge
    const clientData = new TextEncoder().encode(
        JSON.stringify({
            challenge: challenge.challenge,
            type: 'key.get',
        }),
    );

    const signature = crypto.sign(undefined, clientData, privateKeyPem);

    const clientDataB64 = base64UrlEncode(clientData);
    const signatureB64 = base64UrlEncode(new Uint8Array(signature));

    // Submit the signed challenge
    const actionUrl = `${apiBaseUrl}/auth/action`;
    let signResponse: Response;
    try {
        signResponse = await fetch(actionUrl, {
            body: JSON.stringify({
                challengeIdentifier: challenge.challengeIdentifier,
                firstFactor: {
                    credentialAssertion: {
                        clientData: clientDataB64,
                        credId,
                        signature: signatureB64,
                    },
                    kind: 'Key',
                },
            }),
            headers: {
                Authorization: `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
            method: 'POST',
        });
    } catch (error) {
        throwSignerError(SignerErrorCode.HTTP_ERROR, {
            cause: error,
            message: 'Dfns network request failed',
            url: actionUrl,
        });
    }

    if (!signResponse.ok) {
        const errorText = await signResponse.text().catch(() => 'Failed to read error response');
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Dfns auth/action failed: ${signResponse.status}`,
            response: errorText,
            status: signResponse.status,
        });
    }

    let actionResponse: UserActionResponse;
    try {
        actionResponse = (await signResponse.json()) as UserActionResponse;
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Dfns auth action response',
        });
    }

    return actionResponse.userAction;
}
