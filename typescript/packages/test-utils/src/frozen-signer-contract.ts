import type { SolanaSigner } from '@solana/keychain-core';

/**
 * Matches the `TypeError` messages engines raise when code mutates a property
 * of a frozen object under strict mode. The wording varies by engine and by
 * the kind of mutation — overwriting an existing property, adding a new one,
 * defining one, or deleting one:
 *
 * - V8: `Cannot assign to read only property 'x' of object '#<Signer>'`
 * - V8: `Cannot add property x, object is not extensible`
 * - V8: `Cannot define property x, object is not extensible`
 * - V8: `Cannot delete property 'x' of #<Signer>`
 * - JavaScriptCore: `Attempted to assign to readonly property.`
 */
const FROZEN_WRITE_MESSAGE = /read[ -]?only property|not extensible|Cannot delete property|Attempted to assign to/i;

/**
 * Asserts that a signer can still sign after `Object.freeze`.
 *
 * `@solana/signers` freezes a signer when it is attached to a transaction
 * message via `setTransactionMessageFeePayerSigner`, so every signer must treat
 * its own instance as immutable once constructed. A signer that lazily caches
 * state by assigning to `this` — an access token, a derived key, a client
 * handle — throws a `TypeError` on the first cache write and fails for every
 * caller that builds transactions the standard way.
 *
 * `Object.freeze` is shallow, so a cache held in a nested object created during
 * construction stays writable and satisfies this contract.
 *
 * Call this from a package's unit suite with the same mocks the happy-path
 * signing test uses:
 *
 * ```ts
 * it('signs when the signer instance is frozen', async () => {
 *     mockSignResponse();
 *     const signer = await createFooSigner(config);
 *     await assertSignerSurvivesFreeze(signer, () => signer.signTransactions([tx]));
 * });
 * ```
 *
 * @param signer - A fully constructed signer. Freeze happens here, so any
 *   async `init()` must already have resolved.
 * @param exercise - Invokes the signing path under test. Its resolved value is
 *   returned so callers can make their own assertions on the signatures.
 */
export async function assertSignerSurvivesFreeze<TReturn>(
    signer: SolanaSigner,
    exercise: () => Promise<TReturn>,
): Promise<TReturn> {
    Object.freeze(signer);
    try {
        return await exercise();
    } catch (error) {
        if (error instanceof TypeError && FROZEN_WRITE_MESSAGE.test(error.message)) {
            throw explainFrozenWrite(error);
        }
        throw error;
    }
}

/**
 * Builds a replacement error that keeps the original throw site's frames.
 *
 * `stack` embeds the message in its first line and is materialized when the
 * error is constructed, so annotating in place would leave `message` and
 * `stack` disagreeing and reporters that print `stack` would show none of the
 * guidance. Rebuilding both together keeps them consistent.
 */
function explainFrozenWrite(error: TypeError): Error {
    const explained = new Error(
        `${error.message} — the signer wrote to its own instance while signing. ` +
            '@solana/signers freezes fee-payer signers in setTransactionMessageFeePayerSigner, ' +
            'so state cached during signing must live in a nested object created by the constructor ' +
            '(Object.freeze is shallow).',
    );
    const originalFrames = error.stack?.split('\n').slice(1).join('\n');
    if (originalFrames) {
        explained.stack = `${explained.name}: ${explained.message}\n${originalFrames}`;
    }
    return explained;
}
