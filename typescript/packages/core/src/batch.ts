import { Address } from '@solana/addresses';
import { SignatureBytes } from '@solana/keys';
import { SignatureDictionary } from '@solana/signers';

import { createSignatureDictionary } from './utils.js';

interface BatchSignOptions<T> {
    delay: (index: number) => Promise<void>;
    items: readonly T[];
    signFn: (item: T) => Promise<SignatureBytes>;
    signerAddress: Address;
}

/**
 * Sign a batch of items with delay and signature dictionary creation.
 *
 * Handles the common batch signing loop shared by all signers:
 * 1. Delay between concurrent requests (based on batch index)
 * 2. Call the signer-specific sign function
 * 3. Wrap the result in a `SignatureDictionary`
 *
 * Each signer owns the `signFn` callback, which should perform the
 * actual signing and any signature verification before returning.
 *
 * @param options.items - The messages or transactions to sign.
 * @param options.signFn - Signer-specific function that produces verified `SignatureBytes`.
 * @param options.signerAddress - The signer's public key address.
 * @param options.delay - Delay function (from `createBatchDelay`).
 */
export async function batchSign<T>({
    delay,
    items,
    signFn,
    signerAddress,
}: BatchSignOptions<T>): Promise<readonly SignatureDictionary[]> {
    return await Promise.all(
        items.map(async (item, index) => {
            await delay(index);
            const signature = await signFn(item);
            return createSignatureDictionary({
                signature,
                signerAddress,
            });
        }),
    );
}
