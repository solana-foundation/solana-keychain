import base64
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from solders.keypair import Keypair
from solders.transaction import Transaction

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.cdp import CdpSigner, CdpSignerConfig, create_cdp_signer
from solana_keychain.cdp.jwt import (
    compute_req_hash,
    create_auth_jwt,
    create_wallet_jwt,
    extract_host,
)
from tests.util import create_test_transaction

API_BASE_URL = "https://cdp.example.com"
API_HOST = "cdp.example.com"
API_KEY_ID = "test-key-id"

_API_KEYPAIR = Keypair()
API_KEY_SECRET = base64.b64encode(bytes(_API_KEYPAIR)).decode()
API_PUBLIC_KEY = Ed25519PublicKey.from_public_bytes(bytes(_API_KEYPAIR.pubkey()))

_WALLET_EC_KEY = ec.generate_private_key(ec.SECP256R1())
WALLET_SECRET = base64.b64encode(
    _WALLET_EC_KEY.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
).decode()

_ACCOUNT_KEYPAIR = Keypair()
ADDRESS = str(_ACCOUNT_KEYPAIR.pubkey())
BASE_PATH = f"/platform/v2/solana/accounts/{ADDRESS}"


def make_signer() -> CdpSigner:
    return CdpSigner(
        CdpSignerConfig(
            api_key_id=API_KEY_ID,
            api_key_secret=API_KEY_SECRET,
            wallet_secret=WALLET_SECRET,
            address=ADDRESS,
            api_base_url=API_BASE_URL,
        )
    )


def decode_auth_claims(request: httpx.Request) -> tuple[dict[str, Any], dict[str, Any]]:
    token = request.headers["Authorization"].removeprefix("Bearer ")
    header = pyjwt.get_unverified_header(token)
    claims = pyjwt.decode(token, API_PUBLIC_KEY, algorithms=["EdDSA"])
    return header, claims


def decode_wallet_claims(request: httpx.Request) -> dict[str, Any]:
    token = request.headers["X-Wallet-Auth"]
    return pyjwt.decode(token, _WALLET_EC_KEY.public_key(), algorithms=["ES256"])


def test_extract_host() -> None:
    assert extract_host("https://api.cdp.coinbase.com") == "api.cdp.coinbase.com"
    assert extract_host("https://cdp.example.com:8443/base") == "cdp.example.com:8443"
    with pytest.raises(SignerError) as excinfo:
        extract_host("not a url")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_compute_req_hash_rules() -> None:
    assert compute_req_hash(None) is None
    assert compute_req_hash({}) is None
    ordered = compute_req_hash({"a": 1, "b": {"c": 2, "d": 3}})
    reordered = compute_req_hash({"b": {"d": 3, "c": 2}, "a": 1})
    assert ordered == reordered
    assert ordered is not None


def test_create_auth_jwt_shape() -> None:
    token = create_auth_jwt(API_KEY_ID, API_KEY_SECRET, API_HOST, "GET", "/path")
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA"
    assert header["kid"] == API_KEY_ID
    assert len(header["nonce"]) == 32
    claims = pyjwt.decode(token, API_PUBLIC_KEY, algorithms=["EdDSA"])
    assert claims["sub"] == API_KEY_ID
    assert claims["iss"] == "cdp"
    assert claims["uris"] == [f"GET {API_HOST}/path"]
    assert claims["exp"] - claims["iat"] == 120


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        "!!!not-base64!!!",
        base64.b64encode(bytes(32)).decode(),
        base64.b64encode(bytes(_API_KEYPAIR)[:32] + bytes(32)).decode(),
    ],
)
def test_create_auth_jwt_rejects_invalid_secrets(secret: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        create_auth_jwt(API_KEY_ID, secret, API_HOST, "GET", "/path")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_create_wallet_jwt_shape() -> None:
    body = {"transaction": "abc"}
    token = create_wallet_jwt(WALLET_SECRET, API_HOST, "POST", "/path", body)
    claims = pyjwt.decode(token, _WALLET_EC_KEY.public_key(), algorithms=["ES256"])
    assert claims["uris"] == [f"POST {API_HOST}/path"]
    assert claims["jti"]
    assert claims["reqHash"] == compute_req_hash(body)


def test_create_wallet_jwt_omits_req_hash_for_empty_body() -> None:
    token = create_wallet_jwt(WALLET_SECRET, API_HOST, "POST", "/path", None)
    claims = pyjwt.decode(token, _WALLET_EC_KEY.public_key(), algorithms=["ES256"])
    assert "reqHash" not in claims


@pytest.mark.parametrize(
    "secret",
    ["!!!not-base64!!!", base64.b64encode(b"not-der").decode()],
)
def test_create_wallet_jwt_rejects_invalid_secrets(secret: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        create_wallet_jwt(secret, API_HOST, "POST", "/path", None)
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


@pytest.mark.parametrize(
    "overrides",
    [
        {"api_key_id": ""},
        {"api_key_secret": ""},
        {"wallet_secret": ""},
        {"address": ""},
    ],
)
def test_empty_config_fields_rejected(overrides: dict[str, str]) -> None:
    kwargs: dict[str, Any] = {
        "api_key_id": API_KEY_ID,
        "api_key_secret": API_KEY_SECRET,
        "wallet_secret": WALLET_SECRET,
        "address": ADDRESS,
        "api_base_url": API_BASE_URL,
    }
    kwargs.update(overrides)
    with pytest.raises(SignerError) as excinfo:
        CdpSigner(CdpSignerConfig(**kwargs))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_invalid_address_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        CdpSigner(
            CdpSignerConfig(
                api_key_id=API_KEY_ID,
                api_key_secret=API_KEY_SECRET,
                wallet_secret=WALLET_SECRET,
                address="not-a-pubkey",
                api_base_url=API_BASE_URL,
            )
        )
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_reprs_never_contain_secrets() -> None:
    config = CdpSignerConfig(
        api_key_id=API_KEY_ID,
        api_key_secret=API_KEY_SECRET,
        wallet_secret=WALLET_SECRET,
        address=ADDRESS,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer()
    for text in (repr(config), repr(signer)):
        assert API_KEY_SECRET not in text
        assert WALLET_SECRET not in text


@respx.mock
async def test_sign_message_success_with_both_jwts() -> None:
    message = b"cdp-message"
    signature = _ACCOUNT_KEYPAIR.sign_message(message)
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/message").mock(
        return_value=httpx.Response(200, json={"signature": str(signature)})
    )

    result = await make_signer().sign_message(message)

    assert result == signature
    request = respx.calls.last.request
    header, auth_claims = decode_auth_claims(request)
    assert header["kid"] == API_KEY_ID
    assert auth_claims["uris"] == [f"POST {API_HOST}{BASE_PATH}/sign/message"]
    wallet_claims = decode_wallet_claims(request)
    assert wallet_claims["uris"] == [f"POST {API_HOST}{BASE_PATH}/sign/message"]
    assert wallet_claims["reqHash"] == compute_req_hash({"message": message.decode()})


async def test_sign_message_rejects_non_utf8() -> None:
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"\xff\xfe")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/message").mock(
        return_value=httpx.Response(200, json={"signature": "0OIl-not-base58"})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    short = str(Keypair().pubkey())
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/message").mock(
        return_value=httpx.Response(200, json={"signature": short})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    message = b"cdp-message"
    other_signature = Keypair().sign_message(message)
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/message").mock(
        return_value=httpx.Response(200, json={"signature": str(other_signature)})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_api_error() -> None:
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/message").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


def signed_transaction_b64(transaction: Transaction) -> str:
    signature = _ACCOUNT_KEYPAIR.sign_message(transaction.message_data())
    signed = Transaction.from_bytes(bytes(transaction))
    signed.signatures = [signature]
    return base64.b64encode(bytes(signed)).decode()


@respx.mock
async def test_sign_transaction_success() -> None:
    transaction = create_test_transaction(_ACCOUNT_KEYPAIR.pubkey())
    expected_signature = _ACCOUNT_KEYPAIR.sign_message(transaction.message_data())
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/transaction").mock(
        return_value=httpx.Response(
            200, json={"signedTransaction": signed_transaction_b64(transaction)}
        )
    )

    result = await make_signer().sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == expected_signature
    assert list(transaction.signatures) == [expected_signature]
    request = respx.calls.last.request
    wallet_claims = decode_wallet_claims(request)
    assert wallet_claims["reqHash"] is not None


@respx.mock
async def test_sign_transaction_rejects_tx_where_signer_is_not_required() -> None:
    transaction = create_test_transaction(Keypair().pubkey())
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
async def test_sign_transaction_undecodable_response() -> None:
    transaction = create_test_transaction(_ACCOUNT_KEYPAIR.pubkey())
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/transaction").mock(
        return_value=httpx.Response(200, json={"signedTransaction": "!!!not-base64!!!"})
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_transaction_undeserializable_response() -> None:
    transaction = create_test_transaction(_ACCOUNT_KEYPAIR.pubkey())
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/transaction").mock(
        return_value=httpx.Response(
            200, json={"signedTransaction": base64.b64encode(b"junk").decode()}
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_transaction_unsigned_response_fails_verification() -> None:
    transaction = create_test_transaction(_ACCOUNT_KEYPAIR.pubkey())
    respx.post(f"{API_BASE_URL}{BASE_PATH}/sign/transaction").mock(
        return_value=httpx.Response(
            200,
            json={"signedTransaction": base64.b64encode(bytes(transaction)).decode()},
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_is_available_uses_bearer_only() -> None:
    respx.get(f"{API_BASE_URL}{BASE_PATH}").mock(
        return_value=httpx.Response(200, json={"address": ADDRESS})
    )
    assert await make_signer().is_available()
    request = respx.calls.last.request
    assert "X-Wallet-Auth" not in request.headers
    _, claims = decode_auth_claims(request)
    assert claims["uris"] == [f"GET {API_HOST}{BASE_PATH}"]


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    respx.get(f"{API_BASE_URL}{BASE_PATH}").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    assert not await make_signer().is_available()


async def test_create_cdp_signer_factory() -> None:
    signer = await create_cdp_signer(
        CdpSignerConfig(
            api_key_id=API_KEY_ID,
            api_key_secret=API_KEY_SECRET,
            wallet_secret=WALLET_SECRET,
            address=ADDRESS,
            api_base_url=API_BASE_URL,
        )
    )
    assert str(signer.pubkey) == ADDRESS
