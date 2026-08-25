import pytest
from solders.keypair import Keypair

from solana_keychain.core import SignerError, SignerErrorCode, verify_returned_signature


def test_returns_signature_when_it_verifies() -> None:
    keypair = Keypair()
    message = b"payload"
    signature = keypair.sign_message(message)
    assert verify_returned_signature(signature, keypair.pubkey(), message) == signature


def test_raises_signing_failed_on_mismatch() -> None:
    keypair = Keypair()
    signature = keypair.sign_message(b"payload")
    with pytest.raises(SignerError) as excinfo:
        verify_returned_signature(signature, Keypair().pubkey(), b"payload")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
