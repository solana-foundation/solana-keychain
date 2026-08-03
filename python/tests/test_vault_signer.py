"""Vault signer tests, ported from the Rust wiremock suite (rust/src/vault/mod.rs)."""

import base64

import httpx
import pytest
import respx
from solders.keypair import Keypair

from solana_keychain import (
    SignerError,
    SignerErrorCode,
    VaultSigner,
    VaultSignerConfig,
    create_vault_signer,
)
from solana_keychain.vault.signer import _strip_vault_signature_prefix
from tests.util import create_test_transaction

VAULT_ADDR = "https://vault.example.com"
VAULT_TOKEN = "test-token"
KEY_NAME = "test-key"
TEST_PUBKEY = "2vfDxWYbhRt7GXiRYKf1Dr5Z8y7zVQCSERbDTKyBaAqQ"

SIGN_URL = f"{VAULT_ADDR}/v1/transit/sign/{KEY_NAME}"
KEYS_URL = f"{VAULT_ADDR}/v1/transit/keys/{KEY_NAME}"


def make_signer(pubkey: str = TEST_PUBKEY) -> VaultSigner:
    return VaultSigner(
        VaultSignerConfig(
            vault_addr=VAULT_ADDR, token=VAULT_TOKEN, key_name=KEY_NAME, pubkey=pubkey
        )
    )


def mock_sign_response(signature_b64: str, prefix: str = "vault:v1:") -> None:
    respx.post(SIGN_URL).mock(
        return_value=httpx.Response(200, json={"data": {"signature": f"{prefix}{signature_b64}"}})
    )


async def test_create_vault_signer_factory() -> None:
    signer = await create_vault_signer(
        VaultSignerConfig(
            vault_addr=VAULT_ADDR, token=VAULT_TOKEN, key_name=KEY_NAME, pubkey=TEST_PUBKEY
        )
    )
    assert str(signer.pubkey) == TEST_PUBKEY


def test_invalid_pubkey_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(pubkey="invalid-pubkey")
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_non_https_vault_addr_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        VaultSigner(
            VaultSignerConfig(
                vault_addr="http://vault.example.com",
                token=VAULT_TOKEN,
                key_name=KEY_NAME,
                pubkey=TEST_PUBKEY,
            )
        )
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_repr_shows_pubkey_and_never_token() -> None:
    signer = make_signer()
    assert repr(signer) == f"VaultSigner(pubkey={TEST_PUBKEY})"
    assert VAULT_TOKEN not in repr(signer)


def test_config_repr_never_contains_token() -> None:
    config = VaultSignerConfig(
        vault_addr=VAULT_ADDR, token=VAULT_TOKEN, key_name=KEY_NAME, pubkey=TEST_PUBKEY
    )
    assert VAULT_TOKEN not in repr(config)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("vault:v1:abc123", "abc123"),
        ("vault:v27:abc123", "abc123"),
        ("abc123", "abc123"),
        ("vault:vx:abc123", "vault:vx:abc123"),
        ("vault:v:abc123", "vault:v:abc123"),
    ],
)
def test_strip_vault_signature_prefix(raw: str, expected: str) -> None:
    assert _strip_vault_signature_prefix(raw) == expected


@respx.mock
async def test_sign_message_success() -> None:
    keypair = Keypair()
    message = b"vault-message"
    signature = keypair.sign_message(message)
    mock_sign_response(base64.b64encode(bytes(signature)).decode("ascii"))

    signer = make_signer(pubkey=str(keypair.pubkey()))
    result = await signer.sign_message(message)

    assert result == signature
    request = respx.calls.last.request
    assert request.headers["X-Vault-Token"] == VAULT_TOKEN
    assert base64.b64encode(message).decode("ascii") in request.content.decode()


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    signing_keypair = Keypair()
    other_keypair = Keypair()
    message = b"vault-message"
    signature = signing_keypair.sign_message(message)
    mock_sign_response(base64.b64encode(bytes(signature)).decode("ascii"))

    signer = make_signer(pubkey=str(other_keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_api_error() -> None:
    respx.post(SIGN_URL).mock(return_value=httpx.Response(401, json={"errors": ["unauthorized"]}))
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_message_missing_signature_in_response() -> None:
    respx.post(SIGN_URL).mock(return_value=httpx.Response(200, json={"data": {}}))
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    respx.post(SIGN_URL).mock(
        return_value=httpx.Response(200, json={"data": {"signature": "vault:v1:!!!"}})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())
    mock_sign_response(base64.b64encode(bytes(signature)).decode("ascii"), prefix="vault:v2:")

    signer = make_signer(pubkey=str(keypair.pubkey()))
    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert result.encoded_transaction
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_is_available_success() -> None:
    respx.get(KEYS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": {"name": KEY_NAME, "supports_signing": True, "type": "ed25519"}},
        )
    )
    assert await make_signer().is_available()


@respx.mock
async def test_is_available_false_for_unsupported_key_type() -> None:
    respx.get(KEYS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": {"name": KEY_NAME, "supports_signing": True, "type": "rsa-2048"}},
        )
    )
    assert not await make_signer().is_available()


@respx.mock
async def test_is_available_false_when_key_does_not_support_signing() -> None:
    respx.get(KEYS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": {"name": KEY_NAME, "supports_signing": False, "type": "ed25519"}},
        )
    )
    assert not await make_signer().is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    respx.get(KEYS_URL).mock(return_value=httpx.Response(403, json={"errors": ["forbidden"]}))
    assert not await make_signer().is_available()


@respx.mock
async def test_error_channels_never_leak_token() -> None:
    respx.post(SIGN_URL).mock(return_value=httpx.Response(500, text="boom"))
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    error = excinfo.value
    for channel in (str(error), repr(error), repr(error.args)):
        assert VAULT_TOKEN not in channel
