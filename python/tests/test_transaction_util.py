import base64

import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import (
    add_signature_to_transaction,
    classify_signed_transaction,
    get_signing_keypair_position,
    has_all_required_signatures,
    serialize_transaction,
)
from tests.util import create_test_transaction, create_two_signer_transaction


def signed_test_transaction() -> tuple[Keypair, Transaction]:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    return keypair, transaction


def test_get_signing_keypair_position_finds_fee_payer() -> None:
    keypair, transaction = signed_test_transaction()
    assert get_signing_keypair_position(transaction, keypair.pubkey()) == 0


def test_get_signing_keypair_position_rejects_non_signer() -> None:
    _, transaction = signed_test_transaction()
    with pytest.raises(SignerError) as excinfo:
        get_signing_keypair_position(transaction, Pubkey.new_unique())
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


def test_add_signature_places_signature_at_signer_position() -> None:
    keypair, transaction = signed_test_transaction()
    signature = keypair.sign_message(transaction.message_data())

    add_signature_to_transaction(transaction, keypair.pubkey(), signature)

    assert list(transaction.signatures) == [signature]


def test_has_all_required_signatures_false_while_slot_is_default() -> None:
    _, transaction = signed_test_transaction()
    assert not has_all_required_signatures(transaction)


def test_classify_marks_fully_signed_transaction_complete() -> None:
    keypair, transaction = signed_test_transaction()
    signature = keypair.sign_message(transaction.message_data())
    add_signature_to_transaction(transaction, keypair.pubkey(), signature)

    result = classify_signed_transaction(transaction, serialize_transaction(transaction), signature)

    assert result.is_complete
    assert result.signature == signature


def test_classify_marks_missing_cosigner_partial() -> None:
    keypair = Keypair()
    transaction = create_two_signer_transaction(keypair.pubkey(), Pubkey.new_unique())
    signature = keypair.sign_message(transaction.message_data())
    add_signature_to_transaction(transaction, keypair.pubkey(), signature)

    result = classify_signed_transaction(transaction, serialize_transaction(transaction), signature)

    assert not result.is_complete


def test_serialize_transaction_round_trips_through_bincode() -> None:
    keypair, transaction = signed_test_transaction()
    signature = keypair.sign_message(transaction.message_data())
    add_signature_to_transaction(transaction, keypair.pubkey(), signature)

    encoded = serialize_transaction(transaction)
    decoded = Transaction.from_bytes(base64.b64decode(encoded))

    assert decoded == transaction
    assert Signature.default() not in decoded.signatures


def test_signed_message_bytes_prefixes_versioned_messages() -> None:
    from solders.instruction import AccountMeta, Instruction
    from solders.message import MessageV0
    from solders.transaction import VersionedTransaction

    from solana_keychain.core import signed_message_bytes

    keypair = Keypair()
    instruction = Instruction(
        Pubkey.from_bytes(bytes(32)), b"", [AccountMeta(keypair.pubkey(), True, True)]
    )
    message = MessageV0.try_compile(keypair.pubkey(), [instruction], [], Hash.default())
    signature = list(VersionedTransaction(message, [keypair]).signatures)[0]

    # A v0 signature covers 0x80 ‖ serialization, which bytes(message) omits.
    assert signed_message_bytes(message) == b"\x80" + bytes(message)
    assert signature.verify(keypair.pubkey(), signed_message_bytes(message))
    assert not signature.verify(keypair.pubkey(), bytes(message))


def test_signed_message_bytes_leaves_legacy_messages_unchanged() -> None:
    from solana_keychain.core import signed_message_bytes

    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    assert signed_message_bytes(transaction.message) == transaction.message_data()
