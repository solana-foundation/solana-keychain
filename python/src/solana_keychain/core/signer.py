"""Core contract definitions for Solana signers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction


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
    """Unified signing contract implemented by every backend."""

    @property
    @abstractmethod
    def pubkey(self) -> Pubkey:
        """The public key of this signer."""

    @abstractmethod
    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        """Sign ``transaction`` (modified in place) and return the encoded result."""

    @abstractmethod
    async def sign_message(self, message: bytes) -> Signature:
        """Sign arbitrary message bytes."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether the signer is available and healthy."""
