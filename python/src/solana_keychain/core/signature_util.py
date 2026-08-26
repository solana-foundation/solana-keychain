"""Signature verification shared by every backend that receives signatures from a
remote service."""

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.transaction_util import get_signing_keypair_position


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
    try:
        returned = VersionedTransaction.from_bytes(returned_transaction_bytes)
    except Exception:
        raise SignerError(
            SignerErrorCode.SERIALIZATION_ERROR,
            f"Failed to deserialize signed transaction returned by {provider_name}",
        ) from None

    position = get_signing_keypair_position(returned, public_key)
    signatures = returned.signatures
    if position >= len(signatures) or signatures[position] == Signature.default():
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            f"{provider_name} returned a transaction without the signer's signature",
        )
    return verify_returned_signature(signatures[position], public_key, original_message_bytes)
