"""Core contract definitions for Solana signers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TypeVar

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode

_T = TypeVar("_T")


def require_initialized(value: _T | None, signer_name: str) -> _T:
    """Return state resolved by ``init()``, raising ``NOT_INITIALIZED`` when the
    signer has not been initialized yet."""
    if value is None:
        raise SignerError(
            SignerErrorCode.NOT_INITIALIZED,
            f"{signer_name} is not initialized; call init() before signing",
        )
    return value


@dataclass(frozen=True)
class SignedTransaction:
    """Result of a sign_transaction call.

    ``encoded_transaction`` is ``base64(bincode(tx))``. ``is_complete`` is True when
    every required signature slot is populated, False when other signers still need
    to sign.
    """

    encoded_transaction: str
    signature: Signature
    is_complete: bool


class SolanaSigner(ABC):
    """Base contract every backend implements: identity, message signing and health.

    Transaction handling lives in the capability classes, and a backend subclasses
    exactly the one matching its provider's shape:

    - ``TransactionSigner``: signs the caller's transaction as given and leaves
      broadcasting to the caller.
    - ``ModifyingSigner``: rewrites the transaction before signing it; the caller
      must continue from the returned transaction.
    - ``SendingSigner``: the provider signs and broadcasts server-side; the
      caller's transaction is never mutated.
    """

    @property
    @abstractmethod
    def pubkey(self) -> Pubkey:
        """The public key of this signer."""

    @abstractmethod
    async def sign_message(self, message: bytes) -> Signature:
        """Sign arbitrary message bytes."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether the signer is available and healthy."""


class TransactionSigner(SolanaSigner):
    """A signer that signs the caller's transaction exactly as given.

    The transaction's message bytes are what the signature covers; the caller
    broadcasts the result.
    """

    @abstractmethod
    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign ``transaction`` (modified in place) and return the encoded result.

        Accepts legacy, v0 and v1."""


class ModifyingSigner(SolanaSigner):
    """A signer whose provider rewrites the transaction before signing it.

    The returned signature covers the rewritten message, not the bytes the caller
    supplied, so any signatures collected beforehand are invalidated. Run a
    modifying signer first and continue from the transaction it returns.
    """

    @abstractmethod
    async def modify_and_sign_transaction(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        """Let the provider rewrite ``transaction``, sign the rewritten
        transaction and replace ``transaction`` with it.

        On success ``transaction`` holds the provider's rewritten transaction;
        continue from it, never from the bytes submitted."""


class SendingSigner(SolanaSigner):
    """A signer whose provider signs and broadcasts the transaction server-side.

    The provider may rewrite the transaction before broadcasting; the caller's
    transaction is never mutated, and the returned signature identifies the
    transaction that actually landed. A failed call does not mean nothing landed:
    ``BROADCAST_UNCONFIRMED`` carries the provider transaction id when the create
    was accepted.
    """

    @abstractmethod
    async def sign_and_send_transaction(self, transaction: VersionedTransaction) -> Signature:
        """Sign ``transaction`` and broadcast it through the provider."""
