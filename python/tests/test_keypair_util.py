from pathlib import Path

import pytest

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.memory.keypair_util import (
    keypair_from_json_keypair,
    keypair_from_private_key_file,
    keypair_from_private_key_string,
    keypair_from_u8_array_string,
)
from tests.util import TEST_KEYPAIR_BASE58, TEST_KEYPAIR_BYTES, TEST_PUBKEY


def test_from_u8_array_string() -> None:
    keypair = keypair_from_u8_array_string(TEST_KEYPAIR_BYTES)
    assert str(keypair.pubkey()) == TEST_PUBKEY


@pytest.mark.parametrize("invalid", ["[1,2,3]", "[not,a,number]", "[]", "[300,1,2]"])
def test_from_u8_array_string_rejects_invalid(invalid: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        keypair_from_u8_array_string(invalid)
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_from_json_keypair() -> None:
    keypair = keypair_from_json_keypair(TEST_KEYPAIR_BYTES)
    assert str(keypair.pubkey()) == TEST_PUBKEY


@pytest.mark.parametrize("invalid", ['{"not": "an array"}', "not json", "[true, false]"])
def test_from_json_keypair_rejects_invalid(invalid: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        keypair_from_json_keypair(invalid)
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_from_private_key_string_base58() -> None:
    keypair = keypair_from_private_key_string(TEST_KEYPAIR_BASE58)
    assert str(keypair.pubkey()) == TEST_PUBKEY


def test_from_private_key_string_u8_array() -> None:
    keypair = keypair_from_private_key_string(TEST_KEYPAIR_BYTES)
    assert str(keypair.pubkey()) == TEST_PUBKEY


def test_from_private_key_string_invalid() -> None:
    with pytest.raises(SignerError) as excinfo:
        keypair_from_private_key_string("clearly-not-a-valid-key")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_from_private_key_string_does_not_read_file_path(tmp_path: Path) -> None:
    file_path = tmp_path / "keypair.json"
    file_path.write_text(TEST_KEYPAIR_BYTES)
    with pytest.raises(SignerError) as excinfo:
        keypair_from_private_key_string(str(file_path))
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_from_private_key_file(tmp_path: Path) -> None:
    file_path = tmp_path / "keypair.json"
    file_path.write_text(TEST_KEYPAIR_BYTES)
    keypair = keypair_from_private_key_file(str(file_path))
    assert str(keypair.pubkey()) == TEST_PUBKEY


def test_from_private_key_file_missing_is_io_error() -> None:
    with pytest.raises(SignerError) as excinfo:
        keypair_from_private_key_file("/tmp/definitely-missing-keypair-file.json")
    assert excinfo.value.code == SignerErrorCode.IO_ERROR


def test_from_private_key_file_undecodable_content_never_leaks_bytes(tmp_path: Path) -> None:
    secret = b"\x80\x81SECRET_KEY_MATERIAL\xff\xfe"
    file_path = tmp_path / "binary-key.bin"
    file_path.write_bytes(secret)

    with pytest.raises(SignerError) as excinfo:
        keypair_from_private_key_file(str(file_path))

    error = excinfo.value
    assert error.code == SignerErrorCode.IO_ERROR
    for channel in (str(error), repr(error), repr(error.args)):
        assert "SECRET_KEY_MATERIAL" not in channel
