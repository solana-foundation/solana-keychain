"""Signature verification shared by every backend that receives signatures from a
remote service."""

import base64
import binascii

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.transaction_util import (
    get_signing_keypair_position,
    signed_message_bytes,
)


def verify_returned_signature(
    signature: Signature, public_key: Pubkey, message: bytes
) -> Signature:
    """Verify a signature returned by a signing backend against the expected public
    key and message, raising ``SIGNING_FAILED`` on mismatch."""
    if not signature.verify(public_key, message):
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Signature verification failed: the returned signature does not match the public key",
        )
    return signature


def _deserialize_returned_transaction(
    returned_transaction_bytes: bytes, provider_name: str
) -> VersionedTransaction:
    try:
        return VersionedTransaction.from_bytes(returned_transaction_bytes)
    except Exception:
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR,
            f"Failed to deserialize signed transaction returned by {provider_name}",
        ) from None


def _signature_at_signer_position(
    transaction: VersionedTransaction, public_key: Pubkey, provider_name: str
) -> Signature:
    """Locate the signature by ``public_key``'s required-signer position rather
    than assuming it occupies slot zero."""
    position = get_signing_keypair_position(transaction, public_key)
    signatures = transaction.signatures
    if position >= len(signatures) or signatures[position] == Signature.default():
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            f"{provider_name} returned a transaction without the signer's signature",
        )
    return signatures[position]


def extract_and_verify_returned_signature(
    returned_transaction_bytes: bytes,
    public_key: Pubkey,
    original_message_bytes: bytes,
    provider_name: str,
) -> Signature:
    """Extract ``public_key``'s signature from a fully signed wire transaction
    returned by ``provider_name`` and verify it.

    The signature is verified against the locally computed
    ``original_message_bytes`` — never against the returned transaction's own
    message — so a provider cannot substitute a different transaction.
    """
    returned = _deserialize_returned_transaction(returned_transaction_bytes, provider_name)
    signature = _signature_at_signer_position(returned, public_key, provider_name)
    return verify_returned_signature(signature, public_key, original_message_bytes)


def extract_and_verify_rewritten_transaction(
    returned_transaction_bytes: bytes, public_key: Pubkey, provider_name: str
) -> tuple[VersionedTransaction, Signature]:
    """Extract and verify ``public_key``'s signature from a wire transaction
    ``provider_name`` rewrote before signing it.

    The signature is verified against the returned transaction's own message,
    because those are the bytes it covers. Both are handed back: the caller has
    to continue from these, not from the ones it submitted, and the provider is
    trusted for the rewrite itself.
    """
    returned = _deserialize_returned_transaction(returned_transaction_bytes, provider_name)
    signature = _signature_at_signer_position(returned, public_key, provider_name)
    verify_returned_signature(signature, public_key, signed_message_bytes(returned.message))
    return returned, signature


_ED25519_SPKI_PREFIX = bytes(
    (0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00)
)


def public_key_from_spki_der(der: bytes) -> Pubkey | None:
    """Extract the Ed25519 public key carried by a DER-encoded
    SubjectPublicKeyInfo, or ``None`` when the bytes are not one."""
    if len(der) != len(_ED25519_SPKI_PREFIX) + 32:
        return None
    if not der.startswith(_ED25519_SPKI_PREFIX):
        return None
    return Pubkey(der[len(_ED25519_SPKI_PREFIX) :])


def public_key_from_spki_pem(pem: str) -> Pubkey | None:
    """Extract the Ed25519 public key carried by a PEM-encoded
    SubjectPublicKeyInfo, or ``None`` when the text is not one."""
    body = "".join(
        line.strip() for line in pem.splitlines() if not line.startswith("-----")
    )
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None
    return public_key_from_spki_der(der)
