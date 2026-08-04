import base64
import hashlib
import json
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.openfort import (
    OpenfortSigner,
    OpenfortSignerConfig,
    create_openfort_signer,
)
from solana_keychain.openfort.jwt import compute_req_hash, create_wallet_jwt, extract_host
from tests.util import create_test_transaction

API_BASE_URL = "https://openfort.example.com"
API_HOST = "openfort.example.com"
SECRET_KEY = "sk_test_secret-key-value"
ACCOUNT_ID = "acc_12345678-1234-1234-1234-123456789abc"
ACCOUNT_URL = f"{API_BASE_URL}/v2/accounts/{ACCOUNT_ID}"
SIGN_URL = f"{API_BASE_URL}/v2/accounts/backend/{ACCOUNT_ID}/sign"

_WALLET_EC_KEY = ec.generate_private_key(ec.SECP256R1())
_WALLET_DER = _WALLET_EC_KEY.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
WALLET_SECRET = base64.b64encode(_WALLET_DER).decode()
WALLET_SECRET_PEM = _WALLET_EC_KEY.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
).decode()


def make_signer(**overrides: Any) -> OpenfortSigner:
    config = OpenfortSignerConfig(
        secret_key=overrides.pop("secret_key", SECRET_KEY),
        account_id=overrides.pop("account_id", ACCOUNT_ID),
        wallet_secret=overrides.pop("wallet_secret", WALLET_SECRET),
        api_base_url=overrides.pop("api_base_url", API_BASE_URL),
        **overrides,
    )
    return OpenfortSigner(config)


def mock_account(address: str) -> None:
    respx.get(ACCOUNT_URL).mock(
        return_value=httpx.Response(
            200, json={"id": ACCOUNT_ID, "address": address, "chainId": 101}
        )
    )


def mock_sign_response(signature_hex: str) -> None:
    respx.post(SIGN_URL).mock(
        return_value=httpx.Response(
            200,
            json={"object": "signature", "account": ACCOUNT_ID, "signature": signature_hex},
        )
    )


async def initialized_signer(keypair: Keypair, **overrides: Any) -> OpenfortSigner:
    mock_account(str(keypair.pubkey()))
    signer = make_signer(**overrides)
    await signer.init()
    return signer


def test_extract_host() -> None:
    assert extract_host("https://api.openfort.io") == "api.openfort.io"
    assert extract_host("https://openfort.example.com:8443") == "openfort.example.com:8443"
    with pytest.raises(SignerError) as excinfo:
        extract_host("not a url")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@pytest.mark.parametrize(
    "wallet_secret",
    [
        WALLET_SECRET,
        WALLET_SECRET_PEM,
        WALLET_SECRET[:32] + " \n" + WALLET_SECRET[32:],
    ],
)
def test_create_wallet_jwt_accepts_der_and_pem_forms(wallet_secret: str) -> None:
    body = {"data": "0xabcd"}
    token = create_wallet_jwt(wallet_secret, API_HOST, "POST", "/path", body)
    claims = pyjwt.decode(token, _WALLET_EC_KEY.public_key(), algorithms=["ES256"])
    assert claims["uris"] == [f"POST {API_HOST}/path"]
    assert claims["jti"]
    assert claims["exp"] - claims["iat"] == 120
    assert claims["reqHash"] == compute_req_hash(body)


def test_compute_req_hash_is_key_order_independent() -> None:
    body_hash = compute_req_hash({"b": 2, "a": {"d": 4, "c": 3}})
    assert body_hash == compute_req_hash({"a": {"c": 3, "d": 4}, "b": 2})
    assert body_hash == hashlib.sha256(b'{"a":{"c":3,"d":4},"b":2}').hexdigest()


@pytest.mark.parametrize("secret", ["!!!not-a-key!!!", base64.b64encode(b"junk").decode()])
def test_create_wallet_jwt_rejects_invalid_secret(secret: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        create_wallet_jwt(secret, API_HOST, "POST", "/path", {})
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


@pytest.mark.parametrize(
    "overrides",
    [{"secret_key": ""}, {"account_id": ""}, {"wallet_secret": ""}],
)
def test_empty_config_fields_rejected(overrides: dict[str, str]) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(**overrides)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_non_https_base_url_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(api_base_url="http://openfort.example.com")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_resolves_account_address() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()
    request = respx.calls.last.request
    assert request.headers["Authorization"] == f"Bearer {SECRET_KEY}"
    assert "x-wallet-auth" not in request.headers


@respx.mock
async def test_init_rejects_non_solana_address() -> None:
    mock_account("0xE5f4d1a9B23c")
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_api_error() -> None:
    respx.get(ACCOUNT_URL).mock(return_value=httpx.Response(401, json={"error": "denied"}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_uninitialized_sign_raises_not_initialized() -> None:
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_message_success_with_wallet_jwt() -> None:
    keypair = Keypair()
    message = b"openfort-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_response(f"0x{bytes(signature).hex()}")

    result = await signer.sign_message(message)

    assert result == signature
    request = respx.calls.last.request
    assert request.headers["Authorization"] == f"Bearer {SECRET_KEY}"
    body = json.loads(request.content)
    assert body == {"data": f"0x{message.hex()}"}
    claims = pyjwt.decode(
        request.headers["x-wallet-auth"], _WALLET_EC_KEY.public_key(), algorithms=["ES256"]
    )
    assert claims["uris"] == [f"POST {API_HOST}/v2/accounts/backend/{ACCOUNT_ID}/sign"]
    assert claims["reqHash"] == compute_req_hash(body)


@respx.mock
async def test_sign_message_accepts_unprefixed_hex_signature() -> None:
    keypair = Keypair()
    message = b"openfort-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_response(bytes(signature).hex())

    assert await signer.sign_message(message) == signature


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_response("0xzz")
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_response("0x" + "ab" * 32)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    keypair = Keypair()
    message = b"openfort-message"
    signer = await initialized_signer(keypair)
    mock_sign_response(f"0x{bytes(Keypair().sign_message(message)).hex()}")
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
    signature = keypair.sign_message(transaction.message_data())
    mock_sign_response(f"0x{bytes(signature).hex()}")

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


async def test_uninitialized_is_available_false() -> None:
    assert not await make_signer().is_available()


@respx.mock
async def test_is_available_true_when_address_matches() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert await signer.is_available()


@respx.mock
async def test_is_available_false_when_address_changed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_account(str(Keypair().pubkey()))
    assert not await signer.is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(ACCOUNT_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_openfort_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_account(str(keypair.pubkey()))
    signer = await create_openfort_signer(
        OpenfortSignerConfig(
            secret_key=SECRET_KEY,
            account_id=ACCOUNT_ID,
            wallet_secret=WALLET_SECRET,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


def _assert_channels_clean(error: SignerError) -> None:
    for channel in (str(error), repr(error), repr(error.args)):
        assert SECRET_KEY not in channel
        assert WALLET_SECRET not in channel


@respx.mock
async def test_redaction_across_failure_modes() -> None:
    keypair = Keypair()

    respx.get(ACCOUNT_URL).mock(return_value=httpx.Response(401, json={"error": SECRET_KEY}))
    signer = make_signer()
    with pytest.raises(SignerError) as init_error:
        await signer.init()
    _assert_channels_clean(init_error.value)

    signer = await initialized_signer(keypair)
    respx.post(SIGN_URL).mock(
        return_value=httpx.Response(500, text=f"boom {SECRET_KEY} {WALLET_SECRET}")
    )
    with pytest.raises(SignerError) as sign_error:
        await signer.sign_message(b"hello")
    _assert_channels_clean(sign_error.value)

    with pytest.raises(SignerError) as jwt_error:
        create_wallet_jwt("!!!bad!!!", API_HOST, "POST", "/p", {})
    _assert_channels_clean(jwt_error.value)


def test_reprs_never_contain_secrets() -> None:
    config = OpenfortSignerConfig(
        secret_key=SECRET_KEY,
        account_id=ACCOUNT_ID,
        wallet_secret=WALLET_SECRET,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer()
    for text in (repr(config), repr(signer)):
        assert SECRET_KEY not in text
        assert WALLET_SECRET not in text
