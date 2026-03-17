import { getBase64Encoder } from '@solana/codecs-strings';
import {
    base64UrlDecoder,
    sanitizeRemoteErrorResponse,
    SignerErrorCode,
    throwSignerError,
} from '@solana/keychain-core';

import type { UserActionInitResponse, UserActionResponse } from './types.js';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;

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
            response: sanitizeRemoteErrorResponse(errorText),
            status: initResponse.status,
        });
    }

    let rawChallenge: unknown;
    try {
        rawChallenge = await initResponse.json();
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Dfns auth challenge response',
        });
    }

    const challenge = parseUserActionInitResponse(rawChallenge);

    // Verify credential is allowed
    const allowed = challenge.allowCredentials.key.some(
        c => isObject(c) && typeof c.id === 'string' && c.id === credId,
    );
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

    const clientDataB64 = base64UrlDecoder(clientData);
    const signatureB64 = base64UrlDecoder(await signClientData(clientData, privateKeyPem));

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
            response: sanitizeRemoteErrorResponse(errorText),
            status: signResponse.status,
        });
    }

    let rawActionResponse: unknown;
    try {
        rawActionResponse = await signResponse.json();
    } catch (error) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            cause: error,
            message: 'Failed to parse Dfns auth action response',
        });
    }

    const actionResponse = parseUserActionResponse(rawActionResponse);

    return actionResponse.userAction;
}

function parseUserActionInitResponse(raw: unknown): UserActionInitResponse {
    if (!isObject(raw) || !isObject(raw.allowCredentials) || !Array.isArray(raw.allowCredentials.key)) {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns auth challenge response shape',
        });
    }

    if (typeof raw.challenge !== 'string' || typeof raw.challengeIdentifier !== 'string') {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns auth challenge response shape',
        });
    }

    return raw as unknown as UserActionInitResponse;
}

function parseUserActionResponse(raw: unknown): UserActionResponse {
    if (!isObject(raw) || typeof raw.userAction !== 'string') {
        throwSignerError(SignerErrorCode.PARSING_ERROR, {
            message: 'Unexpected Dfns auth action response shape',
        });
    }

    return raw as unknown as UserActionResponse;
}

function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

async function signClientData(clientData: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            message: 'Web Crypto API is not available in this runtime',
        });
    }

    try {
        const privateKey = await subtle.importKey('pkcs8', toArrayBuffer(pemToPkcs8(privateKeyPem)), 'Ed25519', false, [
            'sign',
        ]);
        const signature = await subtle.sign('Ed25519', privateKey, toArrayBuffer(clientData));
        return new Uint8Array(signature);
    } catch (error) {
        throwSignerError(SignerErrorCode.SIGNING_FAILED, {
            cause: error,
            message: 'Failed to sign Dfns auth challenge',
        });
    }
}

function pemToPkcs8(privateKeyPem: string): Uint8Array {
    const normalizedPem = privateKeyPem.replace(/\r/g, '').trim();
    const pemBody = normalizedPem
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s+/g, '');

    if (!pemBody) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'privateKeyPem must be a non-empty PKCS#8 PEM key',
        });
    }

    try {
        base64Encoder ||= getBase64Encoder();
        return new Uint8Array(base64Encoder.encode(pemBody));
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'privateKeyPem must be a valid PKCS#8 PEM key',
        });
    }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return new Uint8Array(bytes).buffer;
}
