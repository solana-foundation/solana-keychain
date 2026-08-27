"""Memory-based local keypair signer."""

from dataclasses import dataclass

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.signer import SignedTransaction, TransactionSigner
from solana_keychain.core.transaction_util import (
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.memory.keypair_util import (
    keypair_from_bytes,
    keypair_from_private_key_file,
    keypair_from_private_key_string,
)


@dataclass(frozen=True)
class MemorySignerConfig:
    keypair: Keypair


class MemorySigner(TransactionSigner):
    """In-memory Ed25519 signer. The private key is held in process memory; this
    backend is intended for local development and testing."""

    def __init__(self, keypair: Keypair) -> None:
        self._keypair = keypair

    def __repr__(self) -> str:
        return f"MemorySigner(pubkey={self.pubkey})"

    @classmethod
    def from_config(cls, config: MemorySignerConfig) -> "MemorySigner":
        return cls(config.keypair)

    @classmethod
    def from_bytes(cls, private_key: bytes) -> "MemorySigner":
        """Build from raw private key bytes: 64 (seed ‖ pubkey, validated) or 32 (seed)."""
        return cls(keypair_from_bytes(private_key))

    @classmethod
    def from_private_key_string(cls, private_key: str) -> "MemorySigner":
        """Build from a base58 string or a u8-array string like ``"[1, 2, ..., 64]"``."""
        return cls(keypair_from_private_key_string(private_key))

    @classmethod
    def from_private_key_file(cls, path: str) -> "MemorySigner":
        """Build from a Solana CLI keypair JSON file."""
        return cls(keypair_from_private_key_file(path))

    @property
    def pubkey(self) -> Pubkey:
        return self._keypair.pubkey()

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        signature = self._keypair.sign_message(signed_message_bytes(transaction.message))
        add_signature_to_transaction(transaction, self.pubkey, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return self._keypair.sign_message(message)

    async def is_available(self) -> bool:
        return True


async def create_memory_signer(config: MemorySignerConfig) -> MemorySigner:
    """Create a ready-to-use memory signer."""
    return MemorySigner.from_config(config)
