from pathlib import Path

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_keychain import MemorySigner, MemorySignerConfig, SignerError, SignerErrorCode
from solana_keychain.core import signed_message_bytes
from tests.util import (
    TEST_KEYPAIR_BASE58,
    TEST_KEYPAIR_BYTES,
    TEST_PUBKEY,
    create_test_transaction,
)


def create_test_signer() -> MemorySigner:
    return MemorySigner.from_private_key_string(TEST_KEYPAIR_BYTES)


def test_create_from_u8_array() -> None:
    assert str(create_test_signer().pubkey) == TEST_PUBKEY


def test_does_not_broadcast_transactions() -> None:
    assert not create_test_signer().broadcasts_transactions


def test_create_from_config() -> None:
    keypair = Keypair.from_base58_string(TEST_KEYPAIR_BASE58)
    signer = MemorySigner.from_config(MemorySignerConfig(keypair=keypair))
    assert str(signer.pubkey) == TEST_PUBKEY


def test_create_from_bytes_rejects_wrong_length() -> None:
    with pytest.raises(SignerError) as excinfo:
        MemorySigner.from_bytes(b"\x01\x02\x03")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_create_from_file(tmp_path: Path) -> None:
    file_path = tmp_path / "keypair.json"
    file_path.write_text(TEST_KEYPAIR_BYTES)
    signer = MemorySigner.from_private_key_file(str(file_path))
    assert str(signer.pubkey) == TEST_PUBKEY


def test_repr_shows_pubkey_only() -> None:
    assert repr(create_test_signer()) == f"MemorySigner(pubkey={TEST_PUBKEY})"


async def test_sign_message() -> None:
    signer = create_test_signer()
    message = b"Hello Solana!"
    signature = await signer.sign_message(message)
    assert signature.verify(signer.pubkey, message)


async def test_sign_transaction() -> None:
    signer = create_test_signer()
    transaction = create_test_transaction(signer.pubkey)

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.encoded_transaction
    assert len(bytes(result.signature)) == 64
    assert list(transaction.signatures) == [result.signature]
    assert result.signature.verify(signer.pubkey, signed_message_bytes(transaction.message))


async def test_sign_transaction_rejects_tx_where_signer_is_not_required() -> None:
    signer = create_test_signer()
    transaction = create_test_transaction(Pubkey.new_unique())

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
