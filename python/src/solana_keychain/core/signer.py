"""Core contract definitions for Solana signers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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

    ``transaction`` is the authoritative signed transaction. Most backends sign the
    caller's object in place and return that same object, but a provider may return
    a rewritten message (Fordefi native manual mode replaces the recent blockhash and
    the priority-fee instructions), which ``solders`` cannot apply in place. Always
    continue from ``transaction`` rather than the object passed to
    ``sign_transaction``; only the former is guaranteed to match
    ``encoded_transaction`` and the bytes ``signature`` covers.
    """

    encoded_transaction: str
    signature: Signature
    is_complete: bool
    transaction: VersionedTransaction = field(repr=False, compare=False)


class SolanaSigner(ABC):
    """Unified signing contract implemented by every backend."""

    @property
    @abstractmethod
    def pubkey(self) -> Pubkey:
        """The public key of this signer."""

    @property
    def broadcasts_transactions(self) -> bool:
        """Whether the provider may execute transactions server-side, requiring
        reconciliation by provider transaction ID before retrying."""
        return False

    @abstractmethod
    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign ``transaction`` and return the encoded result.

        Most backends sign the input in place, but a provider may return a
        rewritten message instead, so continue from
        ``SignedTransaction.transaction`` rather than the object passed in.
        Accepts legacy, v0 and v1."""

    @abstractmethod
    async def sign_message(self, message: bytes) -> Signature:
        """Sign arbitrary message bytes."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether the signer is available and healthy."""
