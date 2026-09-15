import base64

import pytest
from solders.keypair import Keypair
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core import (
    SignerError,
    SignerErrorCode,
    extract_and_verify_returned_signature,
    public_key_from_spki_der,
    public_key_from_spki_pem,
    signed_message_bytes,
    verify_returned_signature,
)
from tests.util import create_test_transaction


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


def _signed_transaction_bytes(keypair: Keypair, transaction: VersionedTransaction) -> bytes:
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    signed = VersionedTransaction.populate(transaction.message, [signature])
    return bytes(signed)


def test_extract_and_verify_happy_path() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    message_bytes = signed_message_bytes(transaction.message)
    expected = keypair.sign_message(message_bytes)

    signature = extract_and_verify_returned_signature(
        _signed_transaction_bytes(keypair, transaction), keypair.pubkey(), message_bytes, "Test"
    )
    assert signature == expected


def test_extract_and_verify_pubkey_not_a_signer() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    message_bytes = signed_message_bytes(transaction.message)

    with pytest.raises(SignerError) as excinfo:
        extract_and_verify_returned_signature(
            _signed_transaction_bytes(keypair, transaction),
            Keypair().pubkey(),
            message_bytes,
            "Test",
        )
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


def test_extract_and_verify_default_signature() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    unsigned = VersionedTransaction.populate(transaction.message, [Signature.default()])

    with pytest.raises(SignerError) as excinfo:
        extract_and_verify_returned_signature(
            bytes(unsigned),
            keypair.pubkey(),
            signed_message_bytes(transaction.message),
            "Test",
        )
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


def test_extract_and_verify_signature_over_wrong_message() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    rewritten = create_test_transaction(keypair.pubkey())
    assert signed_message_bytes(rewritten.message) != signed_message_bytes(transaction.message)

    with pytest.raises(SignerError) as excinfo:
        extract_and_verify_returned_signature(
            _signed_transaction_bytes(keypair, rewritten),
            keypair.pubkey(),
            signed_message_bytes(transaction.message),
            "Test",
        )
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


def test_extract_and_verify_malformed_transaction_bytes() -> None:
    keypair = Keypair()
    with pytest.raises(SignerError) as excinfo:
        extract_and_verify_returned_signature(
            b"not a wire transaction", keypair.pubkey(), b"message", "Test"
        )
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


ED25519_SPKI_PREFIX = bytes(
    (0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00)
)


def test_public_key_from_spki_der_extracts_the_key() -> None:
    pubkey = Keypair().pubkey()
    assert public_key_from_spki_der(ED25519_SPKI_PREFIX + bytes(pubkey)) == pubkey


def test_public_key_from_spki_der_rejects_non_ed25519_der() -> None:
    pubkey = Keypair().pubkey()
    foreign_oid = bytearray(ED25519_SPKI_PREFIX + bytes(pubkey))
    foreign_oid[8] = 0x71

    assert public_key_from_spki_der(bytes(foreign_oid)) is None
    assert public_key_from_spki_der(b"") is None
    assert public_key_from_spki_der(ED25519_SPKI_PREFIX + bytes(pubkey)[:31]) is None


def test_public_key_from_spki_pem_extracts_the_key() -> None:
    pubkey = Keypair().pubkey()
    body = base64.b64encode(ED25519_SPKI_PREFIX + bytes(pubkey)).decode("ascii")
    pem = f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"

    assert public_key_from_spki_pem(pem) == pubkey


def test_public_key_from_spki_pem_rejects_text_that_is_not_a_key() -> None:
    assert public_key_from_spki_pem("not a pem") is None
