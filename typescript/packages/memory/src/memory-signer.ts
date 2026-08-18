import { SignerError, SignerErrorCode, SolanaSigner, throwSignerError } from '@solana/keychain-core';
import { signBytes, verifySignature } from '@solana/keys';
import {
    createKeyPairSignerFromBytes,
    createKeyPairSignerFromPrivateKeyBytes,
    createSignerFromKeyPair,
    type KeyPairSigner,
} from '@solana/signers';

import { loadKeypairFile, parsePrivateKeyString } from './keypair-util.js';
import type { MemorySignerConfig } from './types.js';

/**
 * Create a {@link SolanaSigner} backed by an in-memory Ed25519 keypair.
 *
 * The private key never leaves the local process — all signing happens via the
 * Web Crypto API. Useful for development, server-side signing, and integration
 * tests where a remote vendor is overkill.
 *
 * Exactly one source must be provided in the config; see {@link MemorySignerConfig}.
 *
 * @throws {SignerError} `SIGNER_CONFIG_ERROR` when zero or multiple sources are provided.
 * @throws {SignerError} `SIGNER_INVALID_PRIVATE_KEY` for malformed inputs.
 * @throws {SignerError} `SIGNER_IO_ERROR` if a `privateKeyPath` cannot be read.
 */
export async function createMemorySigner<TAddress extends string = string>(
    config: MemorySignerConfig,
): Promise<SolanaSigner<TAddress>> {
    const keyPairSigner = await resolveKeyPairSigner(config);

    return Object.freeze({
        address: keyPairSigner.address,
        isAvailable(): Promise<boolean> {
            return Promise.resolve(true);
        },
        signMessages: keyPairSigner.signMessages,
        signTransactions: keyPairSigner.signTransactions,
    }) as SolanaSigner<TAddress>;
}

/** Create a memory signer from a pre-built `CryptoKeyPair`. */
export async function createMemorySignerFromKeyPair<TAddress extends string = string>(
    keyPair: CryptoKeyPair,
): Promise<SolanaSigner<TAddress>> {
    return await createMemorySigner<TAddress>({ keyPair });
}

/**
 * Create a memory signer from raw private key bytes.
 *
 * Accepts either:
 * - 64 bytes (Solana CLI format: Ed25519 seed concatenated with public key — validates seed↔pubkey match), or
 * - 32 bytes (raw Ed25519 seed — public key is derived).
 */
export async function createMemorySignerFromBytes<TAddress extends string = string>(
    privateKey: Uint8Array,
): Promise<SolanaSigner<TAddress>> {
    return await createMemorySigner<TAddress>({ privateKey });
}

/**
 * Create a memory signer from a private key string. Auto-detects the format:
 * - U8Array form: `"[1, 2, ..., 64]"`
 * - Otherwise: base58
 *
 * Strings are always 64 bytes (Solana CLI convention).
 */
export async function createMemorySignerFromPrivateKeyString<TAddress extends string = string>(
    privateKeyString: string,
): Promise<SolanaSigner<TAddress>> {
    return await createMemorySigner<TAddress>({ privateKeyString });
}

/**
 * Create a memory signer by reading a Solana CLI keypair JSON file from disk.
 *
 * Node-only: dynamically imports `node:fs/promises` only when invoked.
 */
export async function createMemorySignerFromKeypairFile<TAddress extends string = string>(
    privateKeyPath: string,
): Promise<SolanaSigner<TAddress>> {
    return await createMemorySigner<TAddress>({ privateKeyPath });
}

async function resolveKeyPairSigner(config: MemorySignerConfig): Promise<KeyPairSigner> {
    const provided: (keyof MemorySignerConfig)[] = [];
    if (config.keyPair !== undefined) provided.push('keyPair');
    if (config.privateKey !== undefined) provided.push('privateKey');
    if (config.privateKeyString !== undefined) provided.push('privateKeyString');
    if (config.privateKeyPath !== undefined) provided.push('privateKeyPath');

    if (provided.length === 0) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: 'Memory signer requires one of: keyPair, privateKey, privateKeyString, privateKeyPath',
        });
    }
    if (provided.length > 1) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            message: `Memory signer config must have exactly one source, got: ${provided.join(', ')}`,
        });
    }

    if (config.keyPair !== undefined) {
        return await keyPairSignerFromCryptoKeyPair(config.keyPair);
    }

    try {
        if (config.privateKey !== undefined) {
            return await keyPairSignerFromBytesByLength(config.privateKey);
        }
        const bytes =
            config.privateKeyString !== undefined
                ? parsePrivateKeyString(config.privateKeyString)
                : await loadKeypairFile(config.privateKeyPath!);
        return await createKeyPairSignerFromBytes(bytes);
    } catch (error) {
        if (error instanceof SignerError) throw error;
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            cause: error,
            message: 'Invalid private key bytes',
        });
    }
}

/**
 * The other config sources validate that the public key matches the private key
 * upstream, but `createSignerFromKeyPair` derives the address from `publicKey`
 * and signs with `privateKey` without checking they correspond. Prove the match
 * with a probe signature, and pass a fresh pair object so mutating the caller's
 * `CryptoKeyPair` afterwards cannot re-point the signer's key.
 */
async function keyPairSignerFromCryptoKeyPair(keyPair: CryptoKeyPair): Promise<KeyPairSigner> {
    const { privateKey, publicKey } = keyPair;

    let matches: boolean;
    try {
        const probe = crypto.getRandomValues(new Uint8Array(32));
        const probeSignature = await signBytes(privateKey, probe);
        matches = await verifySignature(publicKey, probeSignature, probe);
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to create signer from keyPair — keyPair must be a valid Ed25519 CryptoKeyPair',
        });
    }
    if (!matches) {
        throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
            message: 'keyPair public key does not match its private key',
        });
    }

    try {
        return await createSignerFromKeyPair({ privateKey, publicKey });
    } catch (error) {
        throwSignerError(SignerErrorCode.CONFIG_ERROR, {
            cause: error,
            message: 'Failed to create signer from keyPair — keyPair must be a valid Ed25519 CryptoKeyPair',
        });
    }
}

async function keyPairSignerFromBytesByLength(privateKey: Uint8Array): Promise<KeyPairSigner> {
    if (privateKey.length === 64) {
        return await createKeyPairSignerFromBytes(privateKey);
    }
    if (privateKey.length === 32) {
        return await createKeyPairSignerFromPrivateKeyBytes(privateKey);
    }
    throwSignerError(SignerErrorCode.INVALID_PRIVATE_KEY, {
        message: `Invalid private key length: expected 32 or 64 bytes, got ${privateKey.length}`,
    });
}
