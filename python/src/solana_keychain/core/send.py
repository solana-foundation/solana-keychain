"""Getting a signed transaction on chain, whichever shape the signer has."""

from collections.abc import Awaitable, Callable

from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SolanaSigner

SendTransactionFn = Callable[[str], Awaitable[Signature]]
"""Broadcasts a base64-encoded wire transaction and returns its signature. The
package has no RPC client, so the network hop is always caller-supplied."""


async def sign_and_send_transaction(
    signer: SolanaSigner,
    transaction: VersionedTransaction,
    send_transaction: SendTransactionFn | None = None,
) -> Signature:
    """Sign ``transaction`` and get it on chain with one call.

    A signer whose ``broadcasts_transactions`` is True broadcasts through its
    provider and ``send_transaction`` is never called; any other signer signs and
    ``send_transaction`` broadcasts the encoded result.

    Raises ``CONFIG_ERROR`` when a signer that cannot broadcast is given no
    ``send_transaction``, and ``SIGNING_FAILED`` when the broadcasting signer
    returns no signature or the signed transaction is still missing signatures.
    """
    if signer.broadcasts_transactions:
        signature = await signer.sign_and_send_transaction(transaction)
        if signature == Signature.default():
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "signer returned no signature for the transaction it broadcast",
            )
        return signature

    if send_transaction is None:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            "this signer cannot broadcast transactions; supply send_transaction to "
            "broadcast the signed one",
        )
    signed = await signer.sign_transaction(transaction)
    if not signed.is_complete:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "transaction is still missing signatures after signing and cannot be broadcast",
        )
    return await send_transaction(signed.encoded_transaction)
