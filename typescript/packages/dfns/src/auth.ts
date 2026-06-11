import { getBase64Encoder } from '@solana/codecs-strings';
import {
    base64UrlDecoder,
    fetchSignerJson,
    normalizePrivateKeyPem,
    SignerErrorCode,
    throwSignerError,
} from '@solana/keychain-core';

import type { UserActionInitResponse, UserActionResponse } from './types.js';

let base64Encoder: ReturnType<typeof getBase64Encoder> | undefined;

/** Payload signed once at key import to confirm the resolved algorithm can produce signatures. */
function getProbePayload(): Uint8Array {
    return new TextEncoder().encode('probe');
}

/**
 * A Dfns credential private key that has been imported and bound to its
 * signing algorithm, ready to sign user-action client data repeatedly without
 * re-parsing the PEM.
 */
export interface DfnsCredentialKey {
    /** Sign user-action client data, returning the signature bytes Dfns expects (DER for ECDSA). */
    sign(clientData: Uint8Array): Promise<Uint8Array>;
}

/**
 * Import a Dfns credential private key (PKCS#8 or SEC1 PEM) and resolve its
 * signing algorithm (Ed25519, ECDSA P-256, or RSA). The returned handle reuses
 * the imported key for every sign call.
 *
 * @throws `INVALID_PRIVATE_KEY` when the key cannot be imported with any
 * supported algorithm.
 */
export async function importDfnsCredentialKey(privateKeyPem: string): Promise<DfnsCredentialKey> {
    const normalizedPem = normalizePrivateKeyPem(privateKeyPem);

    let latestError: unknown;
    const subtle = globalThis.crypto?.subtle;
    if (subtle) {
        try {
            const credentialKey = await importWithWebCrypto(subtle, normalizedPem);
            if (credentialKey) {
                return credentialKey;
            }
        } catch (error) {
            latestError = error;
        }
    }

    try {
        const credentialKey = await importWithNodeCrypto(normalizedPem);
        if (credentialKey) {
            return credentialKey;
        }
    } catch (error) {
        latestError = error;
    }

    throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
        cause: latestError,
        message: 'privateKeyPem is not a supported Ed25519, ECDSA P-256, or RSA private key',
    });
}

/**
 * Perform the Dfns User Action Signing flow. For more details, see https://docs.dfns.co/api-reference/auth/signing-flows#asymetric-keys-signing-flow
 *
 * @returns The `userAction` token to include as `x-dfns-useraction` header.
 */
export async function signUserAction(
    apiBaseUrl: string,
    authToken: string,
    credId: string,
    credentialKey: DfnsCredentialKey,
    httpMethod: string,
    httpPath: string,
    body: string,
): Promise<string> {
    // Request a challenge
    const rawChallenge = await fetchSignerJson<unknown>({
        init: {
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
        },
        providerName: 'Dfns',
        url: `${apiBaseUrl}/auth/action/init`,
    });

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
    const signatureB64 = base64UrlDecoder(await credentialKey.sign(clientData));

    // Submit the signed challenge
    const rawActionResponse = await fetchSignerJson<unknown>({
        init: {
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
        },
        providerName: 'Dfns',
        url: `${apiBaseUrl}/auth/action`,
    });

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

async function importWithWebCrypto(
    subtle: SubtleCrypto,
    privateKeyPem: string,
): Promise<DfnsCredentialKey | undefined> {
    const privateKeyDer = toArrayBuffer(pemToDer(privateKeyPem));

    const attempts: ReadonlyArray<{
        importAlgorithm: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams;
        // When true, the WebCrypto output is an IEEE-P1363 (raw r||s) ECDSA
        // signature that must be re-encoded as ASN.1 DER before returning, since
        // Dfns user-action verification expects DER (parity with node:crypto and
        // the Rust implementation). See rust/src/dfns/auth.rs.
        isEcdsa: boolean;
        signAlgorithm: AlgorithmIdentifier | EcdsaParams;
    }> = [
        { importAlgorithm: 'Ed25519', isEcdsa: false, signAlgorithm: 'Ed25519' },
        {
            importAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' },
            isEcdsa: true,
            signAlgorithm: { hash: 'SHA-256', name: 'ECDSA' },
        },
        {
            importAlgorithm: { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' },
            isEcdsa: false,
            signAlgorithm: 'RSASSA-PKCS1-v1_5',
        },
    ];

    for (const attempt of attempts) {
        let privateKey: CryptoKey;
        try {
            privateKey = await subtle.importKey('pkcs8', privateKeyDer, attempt.importAlgorithm, false, ['sign']);
            await subtle.sign(attempt.signAlgorithm, privateKey, toArrayBuffer(getProbePayload()));
        } catch {
            // Try the next key algorithm.
            continue;
        }
        return {
            async sign(clientData: Uint8Array): Promise<Uint8Array> {
                let signature: Uint8Array;
                try {
                    signature = new Uint8Array(
                        await subtle.sign(attempt.signAlgorithm, privateKey, toArrayBuffer(clientData)),
                    );
                } catch (error) {
                    throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                        cause: error,
                        message: 'Failed to sign Dfns auth challenge',
                    });
                }
                return attempt.isEcdsa ? p1363ToDer(signature) : signature;
            },
        };
    }

    return undefined;
}

/**
 * Convert an IEEE-P1363 (raw r||s) P-256 ECDSA signature into an ASN.1
 * DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`. WebCrypto's
 * `subtle.sign({ name: 'ECDSA' }, ...)` returns the 64-byte P1363 form, but
 * Dfns (and node:crypto's default) expect DER.
 */
export function p1363ToDer(raw: Uint8Array): Uint8Array {
    if (raw.length === 0 || raw.length % 2 !== 0) {
        throw new Error(`p1363ToDer: expected an even-length byte array, got ${raw.length}`);
    }
    const half = raw.length / 2;
    const r = encodeDerInteger(raw.subarray(0, half));
    const s = encodeDerInteger(raw.subarray(half));
    const body = new Uint8Array(r.length + s.length);
    body.set(r, 0);
    body.set(s, r.length);

    const out = new Uint8Array(2 + body.length);
    out[0] = 0x30; // SEQUENCE
    out[1] = body.length; // P-256 bodies are always < 128 bytes (single-byte length)
    out.set(body, 2);
    return out;
}

/**
 * DER-encode a single unsigned big-endian integer (an ECDSA `r` or `s`
 * component): strip leading zero bytes to the minimal length, then prepend a
 * `0x00` byte when the high bit of the first content byte is set so the value
 * is interpreted as positive.
 */
function encodeDerInteger(value: Uint8Array): Uint8Array {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0x00) {
        start += 1;
    }
    let content = value.subarray(start);
    if (((content[0] ?? 0) & 0x80) !== 0) {
        const padded = new Uint8Array(content.length + 1);
        padded.set(content, 1);
        content = padded;
    }
    const out = new Uint8Array(2 + content.length);
    out[0] = 0x02; // INTEGER
    out[1] = content.length;
    out.set(content, 2);
    return out;
}

async function importWithNodeCrypto(privateKeyPem: string): Promise<DfnsCredentialKey | undefined> {
    let nodeCrypto: typeof import('node:crypto');
    try {
        nodeCrypto = await import('node:crypto');
    } catch {
        return undefined;
    }

    // Throws when the PEM cannot be parsed or the key type cannot sign without
    // an explicit digest; the caller surfaces this as INVALID_PRIVATE_KEY.
    const privateKey = nodeCrypto.createPrivateKey(privateKeyPem);
    nodeCrypto.sign(undefined, getProbePayload(), privateKey);

    return {
        sign(clientData: Uint8Array): Promise<Uint8Array> {
            try {
                return Promise.resolve(new Uint8Array(nodeCrypto.sign(undefined, clientData, privateKey)));
            } catch (error) {
                throwSignerError(SignerErrorCode.SIGNING_FAILED, {
                    cause: error,
                    message: 'Failed to sign Dfns auth challenge',
                });
            }
        },
    };
}

function pemToDer(normalizedPem: string): Uint8Array {
    const pemBody = normalizedPem
        .replace(/-----BEGIN [^-]+-----/g, '')
        .replace(/-----END [^-]+-----/g, '')
        .replace(/\s+/g, '');

    if (!pemBody) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'privateKeyPem must be a non-empty PEM key',
        });
    }

    try {
        base64Encoder ||= getBase64Encoder();
        return new Uint8Array(base64Encoder.encode(pemBody));
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'privateKeyPem must be a valid PEM key',
        });
    }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return Uint8Array.from(bytes).buffer;
}
