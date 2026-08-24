"""Getting a signed transaction on chain, whichever shape the signer has."""

from collections.abc import Awaitable, Callable

from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SolanaSigner

SendTransactionFn = Callable[[str], Awaitable[Signature]]
"""Broadcasts a base64-encoded wire transaction and returns the signature
identifying it. The package has no RPC client, so the network hop is always
injected: implement it with whatever transport the caller already has, an RPC
client call or a relayer endpoint."""


async def sign_and_send_transaction(
    signer: SolanaSigner,
    transaction: VersionedTransaction,
    send_transaction: SendTransactionFn | None = None,
) -> Signature:
    """Sign ``transaction`` and get it on chain with one call.

    A signer whose ``broadcasts_transactions`` is True has already broadcast the
    transaction through its provider, so its own signature identifies it and
    ``send_transaction`` is never called. Any other signer signs, and
    ``send_transaction`` broadcasts the encoded result.

    Raises ``CONFIG_ERROR`` when a signer that cannot broadcast is given no
    ``send_transaction``, checked before signing so a missing one cannot waste a
    remote signing request, and ``SIGNING_FAILED`` when the signed transaction is
    still missing signatures and therefore cannot land.
    """
    if not signer.broadcasts_transactions:
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

    signed = await signer.sign_transaction(transaction)
    return signed.signature
