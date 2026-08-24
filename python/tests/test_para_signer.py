import asyncio
import json
import logging
from typing import Any

import httpx
import pytest
import respx
from solders.keypair import Keypair

from solana_keychain import ParaSigner, ParaSignerConfig, SignerError, SignerErrorCode
from solana_keychain.core import signed_message_bytes
from solana_keychain.para import create_para_signer
from tests.util import create_test_transaction

API_BASE_URL = "https://para.example.com"
API_KEY = "sk_test-key"
WALLET_ID = "12345678-1234-1234-1234-123456789abc"
WALLET_URL = f"{API_BASE_URL}/v1/wallets/{WALLET_ID}"
SIGN_URL = f"{API_BASE_URL}/v1/wallets/{WALLET_ID}/sign-raw"


def make_signer() -> ParaSigner:
    return ParaSigner(
        ParaSignerConfig(api_key=API_KEY, wallet_id=WALLET_ID, api_base_url=API_BASE_URL)
    )


def mock_wallet_response(
    address: str | None, wallet_type: str = "SOLANA", status: str = "ACTIVE"
) -> None:
    body: dict[str, Any] = {"id": WALLET_ID, "type": wallet_type, "status": status}
    if address is not None:
        body["address"] = address
    respx.get(WALLET_URL).mock(return_value=httpx.Response(200, json=body))


def mock_sign_response(hex_signature: str) -> None:
    respx.post(SIGN_URL).mock(return_value=httpx.Response(200, json={"signature": hex_signature}))


async def initialized_signer(keypair: Keypair) -> ParaSigner:
    mock_wallet_response(str(keypair.pubkey()))
    signer = make_signer()
    await signer.init()
    return signer


@pytest.mark.parametrize(
    ("api_key", "wallet_id"),
    [
        ("bad-key", WALLET_ID),
        ("", WALLET_ID),
        ("sk_test-key", ""),
        ("sk_test-key", "12345678-1234-1234-1234-123456789abg"),
        ("sk_test-key", "123456781234-1234-1234-123456789abcd"),
    ],
)
def test_invalid_config_rejected(api_key: str, wallet_id: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        ParaSigner(
            ParaSignerConfig(api_key=api_key, wallet_id=wallet_id, api_base_url=API_BASE_URL)
        )
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_non_https_base_url_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        ParaSigner(
            ParaSignerConfig(
                api_key=API_KEY, wallet_id=WALLET_ID, api_base_url="http://para.example.com"
            )
        )
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_reprs_never_contain_api_key() -> None:
    config = ParaSignerConfig(api_key=API_KEY, wallet_id=WALLET_ID, api_base_url=API_BASE_URL)
    signer = make_signer()
    assert API_KEY not in repr(config)
    assert API_KEY not in repr(signer)


@respx.mock
async def test_init_resolves_wallet_pubkey() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()
    assert respx.calls.last.request.headers["X-API-Key"] == API_KEY


@respx.mock
async def test_init_rejects_non_solana_wallet() -> None:
    mock_wallet_response("0xabc", wallet_type="ETHEREUM")
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_accepts_lowercase_wallet_type() -> None:
    keypair = Keypair()
    mock_wallet_response(str(keypair.pubkey()), wallet_type="solana")
    signer = make_signer()
    await signer.init()
    assert signer.pubkey == keypair.pubkey()


@respx.mock
async def test_init_warns_on_unusual_status(caplog: pytest.LogCaptureFixture) -> None:
    keypair = Keypair()
    mock_wallet_response(str(keypair.pubkey()), status="CREATING")
    signer = make_signer()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        await signer.init()
    assert any("signing may fail" in record.message for record in caplog.records)


@respx.mock
async def test_init_rejects_missing_address() -> None:
    mock_wallet_response(None)
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_rejects_invalid_address() -> None:
    mock_wallet_response("not-a-pubkey")
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_api_error() -> None:
    respx.get(WALLET_URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_uninitialized_sign_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_message_success() -> None:
    keypair = Keypair()
    message = b"para-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_response(bytes(signature).hex())

    result = await signer.sign_message(message)

    assert result == signature
    parsed = json.loads(respx.calls.last.request.content)
    assert parsed == {"data": message.hex(), "encoding": "hex"}


@respx.mock
async def test_sign_message_accepts_0x_prefixed_signature() -> None:
    keypair = Keypair()
    message = b"para-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_response(f"0x{bytes(signature).hex()}")

    assert await signer.sign_message(message) == signature


@respx.mock
async def test_sign_message_missing_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(SIGN_URL).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_response("ab" * 32)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_response("zz" * 64)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    keypair = Keypair()
    other = Keypair()
    message = b"para-message"
    signer = await initialized_signer(keypair)
    mock_sign_response(bytes(other.sign_message(message)).hex())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(SIGN_URL).mock(return_value=httpx.Response(500, json={"error": "boom"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_sign_response(bytes(signature).hex())

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


@respx.mock
@pytest.mark.parametrize(
    ("wallet_type", "status", "expected"),
    [
        ("SOLANA", "ACTIVE", True),
        ("SOLANA", "READY", True),
        ("solana", "ready", True),
        ("ETHEREUM", "ACTIVE", False),
        ("SOLANA", "CREATING", False),
    ],
)
async def test_is_available_gates_type_and_status(
    wallet_type: str, status: str, expected: bool
) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_wallet_response(str(keypair.pubkey()), wallet_type=wallet_type, status=status)
    assert await signer.is_available() is expected


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(WALLET_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_is_available_false_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    monkeypatch.setattr("solana_keychain.core.http.AVAILABILITY_TIMEOUT_SECONDS", 0.05)

    async def slow_response(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.5)
        return httpx.Response(200, json={})

    respx.get(WALLET_URL).mock(side_effect=slow_response)
    assert not await signer.is_available()


@respx.mock
async def test_create_para_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_wallet_response(str(keypair.pubkey()))
    signer = await create_para_signer(
        ParaSignerConfig(api_key=API_KEY, wallet_id=WALLET_ID, api_base_url=API_BASE_URL)
    )
    assert signer.pubkey == keypair.pubkey()
