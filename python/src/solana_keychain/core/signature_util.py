"""Signature verification shared by every backend that receives signatures from a
remote service."""

from solders.pubkey import Pubkey
from solders.signature import Signature

from solana_keychain.core.errors import SignerError, SignerErrorCode


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
