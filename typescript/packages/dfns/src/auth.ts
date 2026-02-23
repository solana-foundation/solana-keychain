import * as crypto from 'node:crypto';

import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';

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
    const initResponse = await fetch(`${apiBaseUrl}/auth/action/init`, {
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

    if (!initResponse.ok) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Dfns auth/action/init failed: ${initResponse.status}`,
            status: initResponse.status,
        });
    }

    const challenge = (await initResponse.json()) as UserActionInitResponse;

    // Verify credential is allowed
    const allowed = challenge.allowCredentials.key.some(c => c.id === credId);
    if (!allowed) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Credential ${credId} not in allowed credentials`,
        });
    }

    // Sign the challenge
    const clientData = Buffer.from(
        JSON.stringify({
            challenge: challenge.challenge,
            type: 'key.get',
        }),
    );

    const signature = crypto.sign(undefined, clientData, privateKeyPem);

    const clientDataB64 = toBase64Url(clientData);
    const signatureB64 = toBase64Url(signature);

    // Submit the signed challenge
    const signResponse = await fetch(`${apiBaseUrl}/auth/action`, {
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

    if (!signResponse.ok) {
        throwSignerError(SignerErrorCode.REMOTE_API_ERROR, {
            message: `Dfns auth/action failed: ${signResponse.status}`,
            status: signResponse.status,
        });
    }

    const actionResponse = (await signResponse.json()) as UserActionResponse;
    return actionResponse.userAction;
}

function toBase64Url(buffer: Buffer): string {
    return buffer.toString('base64url');
}
