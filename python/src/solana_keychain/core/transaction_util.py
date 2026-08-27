"""Transaction serialization and signature-placement utilities."""

import base64
import hashlib
import uuid

from solders.message import VersionedMessage, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SignedTransaction

ED25519_SIGNATURE_LENGTH = 64


def idempotency_key_from_message(message_bytes: bytes) -> str:
    """A UUID derived from SHA-256(message bytes), so a retry of the same bytes
    reuses the key and the provider deduplicates the create."""
    digest = bytearray(hashlib.sha256(message_bytes).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def serialize_transaction(transaction: VersionedTransaction) -> str:
    """Encode a transaction to base64(bincode(tx))."""
    try:
        raw = bytes(transaction)
    except Exception as error:
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR, f"Failed to serialize transaction: {error}"
        ) from None
    return base64.b64encode(raw).decode("ascii")


def signed_message_bytes(message: VersionedMessage) -> bytes:
    """The bytes a signature over ``message`` actually covers.

    A versioned message is signed with the version prefix its own serialization
    omits (``0x80`` for v0, ``0x81`` for v1); a legacy message is signed as-is.
    """
    return to_bytes_versioned(message)


def get_signing_keypair_position(transaction: VersionedTransaction, pubkey: Pubkey) -> int:
    """Index of ``pubkey`` within the transaction's required-signer slots."""
    num_required = transaction.message.header.num_required_signatures
    account_keys = transaction.message.account_keys
    if len(account_keys) < num_required:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, "Invalid account index: not enough account keys"
        )
    try:
        return account_keys[:num_required].index(pubkey)
    except ValueError:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED, f"Pubkey {pubkey} not found in transaction signers"
        ) from None


def add_signature_to_transaction(
    transaction: VersionedTransaction, pubkey: Pubkey, signature: Signature
) -> None:
    """Place ``signature`` at ``pubkey``'s required-signer position, in place."""
    position = get_signing_keypair_position(transaction, pubkey)
    num_required = transaction.message.header.num_required_signatures
    signatures = list(transaction.signatures)
    while len(signatures) < num_required:
        signatures.append(Signature.default())
    signatures[position] = signature
    transaction.signatures = signatures


def has_all_required_signatures(transaction: VersionedTransaction) -> bool:
    """True when every required signature slot holds a non-default signature."""
    num_required = transaction.message.header.num_required_signatures
    signatures = transaction.signatures
    if len(signatures) < num_required:
        return False
    default = Signature.default()
    return all(sig != default for sig in signatures[:num_required])


def classify_signed_transaction(
    transaction: VersionedTransaction, encoded_transaction: str, signature: Signature
) -> SignedTransaction:
    """Build a SignedTransaction marked complete or partial.

    Carries ``transaction`` through, so callers never have to know whether a
    backend signed the object they passed in.
    """
    return SignedTransaction(
        encoded_transaction=encoded_transaction,
        signature=signature,
        is_complete=has_all_required_signatures(transaction),
        transaction=transaction,
    )
