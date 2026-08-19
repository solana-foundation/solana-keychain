"""Transaction serialization and signature-placement utilities."""

import base64
import hashlib
import uuid

from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SignedTransaction

MESSAGE_VERSION_PREFIX = b"\x80"
ED25519_SIGNATURE_LENGTH = 64


def idempotency_key_from_message(message_bytes: bytes) -> str:
    """A UUID derived from SHA-256(message bytes), so a retry of the same bytes
    reuses the key and the provider deduplicates the create."""
    digest = bytearray(hashlib.sha256(message_bytes).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def assert_unversioned_wire_transaction(provider: str, wire_bytes: bytes) -> None:
    """Reject a wire transaction whose envelope carries a version prefix.

    Legacy and v0 envelopes both open with a compact-u16 signature count, capped
    at 12 signatures, so the high bit of the first byte is never set. v1 moves its
    signatures to the tail and puts ``0x80 | version`` at offset zero, a layout
    the signature-slot readers here cannot interpret.
    """
    if not wire_bytes or not wire_bytes[0] & 0x80:
        return
    raise SignerError(
        SignerErrorCode.SERIALIZATION_ERROR,
        f"{provider} returned a v{wire_bytes[0] & 0x7F} transaction envelope, which is not "
        "supported yet (only legacy and v0 transactions can be verified)",
    )


def serialize_transaction(transaction: Transaction) -> str:
    """Encode a transaction to base64(bincode(tx))."""
    try:
        raw = bytes(transaction)
    except Exception as error:
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR, f"Failed to serialize transaction: {error}"
        ) from None
    return base64.b64encode(raw).decode("ascii")


def signed_message_bytes(message: Message | MessageV0) -> bytes:
    """The bytes a signature over ``message`` actually covers.

    A v0 message is signed with a ``0x80`` version prefix that its serialization
    omits; a legacy message is signed as-is.
    """
    serialized = bytes(message)
    if isinstance(message, MessageV0):
        return MESSAGE_VERSION_PREFIX + serialized
    return serialized


def get_signing_keypair_position(transaction: Transaction, pubkey: Pubkey) -> int:
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
    transaction: Transaction, pubkey: Pubkey, signature: Signature
) -> None:
    """Place ``signature`` at ``pubkey``'s required-signer position, in place."""
    position = get_signing_keypair_position(transaction, pubkey)
    num_required = transaction.message.header.num_required_signatures
    signatures = list(transaction.signatures)
    while len(signatures) < num_required:
        signatures.append(Signature.default())
    signatures[position] = signature
    transaction.signatures = signatures


def has_all_required_signatures(transaction: Transaction) -> bool:
    """True when every required signature slot holds a non-default signature."""
    num_required = transaction.message.header.num_required_signatures
    signatures = transaction.signatures
    if len(signatures) < num_required:
        return False
    default = Signature.default()
    return all(sig != default for sig in signatures[:num_required])


def classify_signed_transaction(
    transaction: Transaction, encoded_transaction: str, signature: Signature
) -> SignedTransaction:
    """Build a SignedTransaction marked complete or partial."""
    return SignedTransaction(
        encoded_transaction=encoded_transaction,
        signature=signature,
        is_complete=has_all_required_signatures(transaction),
    )
