import { Address, generateKeyPair, getAddressDecoder, SignatureBytes, signBytes } from '@solana/kit';

/**
 * A test keypair for unit tests that need valid Ed25519 signatures.
 *
 * Call `createTestKeypair()` to get an address and a `sign` function that
 * produces real Ed25519 signatures matching that address.
 */
export interface TestKeypair {
    /** The base58 address corresponding to this keypair */
    address: Address;
    /** Sign arbitrary bytes with the private key */
    sign(data: Uint8Array): Promise<SignatureBytes>;
}

/**
 * Create a fresh Ed25519 keypair for unit testing.
 *
 * The returned `sign` function produces real signatures that will pass
 * `assertSignatureValid`, so mocked API responses can include valid sigs.
 */
export async function createTestKeypair(): Promise<TestKeypair> {
    const keyPair = await generateKeyPair();
    const publicKeyBytes = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const address = getAddressDecoder().decode(new Uint8Array(publicKeyBytes));
    return {
        address,
        sign: (data: Uint8Array) => signBytes(keyPair.privateKey, data),
    };
}
