import { getBase58Encoder } from '@solana/codecs-strings';
import { SignerErrorCode, throwSignerError } from '@solana/keychain-core';

/** Length of a Solana keypair private key (Ed25519 seed concatenated with public key). */
const PRIVATE_KEY_LENGTH = 64;

let base58Encoder: ReturnType<typeof getBase58Encoder> | undefined;

/**
 * Parse a private key string. Auto-detects the format:
 * - U8Array form: `"[1, 2, ..., 64]"` (Solana CLI keypair JSON, inline)
 * - Otherwise: base58
 *
 * Returns the 64-byte private key (Ed25519 seed concatenated with public key).
 *
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed input or wrong length.
 */
export function parsePrivateKeyString(privateKey: string): Uint8Array {
    const trimmed = privateKey.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        return parseU8ArrayString(trimmed);
    }
    return parseBase58PrivateKey(trimmed);
}

/**
 * Parse a U8Array string of the form `"[1, 2, ..., 64]"`.
 *
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed input or wrong length.
 */
function parseU8ArrayString(arrayStr: string): Uint8Array {
    const trimmed = arrayStr.trim();
    if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            message: "U8Array string must start with '[' and end with ']'",
        });
    }

    const inner = trimmed.slice(1, -1).trim();
    if (inner.length === 0) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            message: 'U8Array string cannot be empty',
        });
    }

    const parts = inner.split(',');
    const bytes = new Uint8Array(parts.length);
    for (let i = 0; i < parts.length; i++) {
        const token = parts[i]!.trim();
        if (!/^\d+$/.test(token)) {
            throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
                message: 'Invalid U8Array private key format',
            });
        }
        const value = Number(token);
        if (!Number.isInteger(value) || value < 0 || value > 255) {
            throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
                message: 'U8Array elements must be byte values (0-255)',
            });
        }
        bytes[i] = value;
    }

    assertPrivateKeyLength(bytes);
    return bytes;
}

/**
 * Parse a base58-encoded private key string.
 *
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed input or wrong length.
 */
function parseBase58PrivateKey(privateKey: string): Uint8Array {
    base58Encoder ||= getBase58Encoder();
    let decoded: Uint8Array;
    try {
        decoded = new Uint8Array(base58Encoder.encode(privateKey));
    } catch (error) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            cause: error,
            message: 'Invalid private key format',
        });
    }
    assertPrivateKeyLength(decoded);
    return decoded;
}

/**
 * Parse a Solana CLI keypair JSON file content (a JSON array of 64 bytes).
 *
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed JSON or wrong length.
 */
function parseJsonKeypair(jsonContent: string): Uint8Array {
    let parsed: unknown;
    try {
        parsed = JSON.parse(jsonContent);
    } catch (error) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            cause: error,
            message: 'Invalid JSON keypair format. Expected a JSON array of 64 bytes',
        });
    }

    if (!Array.isArray(parsed)) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            message: 'Invalid JSON keypair format. Expected a JSON array of 64 bytes',
        });
    }

    const arr = parsed as unknown[];
    const bytes = new Uint8Array(arr.length);
    for (let i = 0; i < arr.length; i++) {
        const value = arr[i];
        if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 255) {
            throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
                message: 'JSON keypair elements must be byte values (0-255)',
            });
        }
        bytes[i] = value;
    }

    assertPrivateKeyLength(bytes);
    return bytes;
}

/**
 * Load a Solana CLI keypair JSON file from disk and parse it into raw bytes.
 *
 * Node-only: dynamically imports `node:fs/promises`. Bundlers targeting browsers
 * will not pull this code unless this function is called.
 *
 * @throws {SignerError} `SIGNER_IO_ERROR` if the file cannot be read.
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed contents.
 */
export async function loadKeypairFile(path: string): Promise<Uint8Array> {
    let content: string;
    try {
        const { readFile } = await import('node:fs/promises');
        content = await readFile(path, 'utf-8');
    } catch (error) {
        throwSignerError(SignerErrorCode.IO_ERROR, {
            cause: error,
            message: 'Failed to read private key file',
        });
    }
    return parseJsonKeypair(content);
}

function assertPrivateKeyLength(bytes: Uint8Array): void {
    if (bytes.length !== PRIVATE_KEY_LENGTH) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            message: `Invalid private key length: expected ${PRIVATE_KEY_LENGTH} bytes, got ${bytes.length}`,
        });
    }
}
