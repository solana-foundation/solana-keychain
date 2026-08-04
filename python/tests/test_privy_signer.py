import base64
import json
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.privy import (
    PrivyAuthorizationContext,
    PrivySigner,
    PrivySignerConfig,
    create_privy_signer,
    format_authorization_signature_payload,
    generate_authorization_signatures,
)
from solana_keychain.privy.authorization import _parse_p256_private_key
from tests.util import create_test_transaction

API_BASE_URL = "https://privy.example.com/v1"
APP_ID = "test-app-id"
APP_SECRET = "test-app-secret"
WALLET_ID = "test-wallet-id"
WALLET_URL = f"{API_BASE_URL}/wallets/{WALLET_ID}"
RPC_URL = f"{API_BASE_URL}/wallets/{WALLET_ID}/rpc"

TEST_P256_PKCS8_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n"
    "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n"
    "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n"
    "-----END PRIVATE KEY-----"
)
TEST_P256_PKCS8_BASE64 = (
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG"
    "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY"
    "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf"
)


def make_signer(
    authorization_context: PrivyAuthorizationContext | None = None,
    authorization_request_expiry_ms: int | None = 15 * 60 * 1000,
) -> PrivySigner:
    return PrivySigner(
        PrivySignerConfig(
            app_id=APP_ID,
            app_secret=APP_SECRET,
            wallet_id=WALLET_ID,
            api_base_url=API_BASE_URL,
            authorization_context=authorization_context,
            authorization_request_expiry_ms=authorization_request_expiry_ms,
        )
    )


def mock_wallet_response(address: str, chain_type: str = "solana") -> None:
    respx.get(WALLET_URL).mock(
        return_value=httpx.Response(
            200, json={"id": WALLET_ID, "address": address, "chain_type": chain_type}
        )
    )


def mock_sign_response(signature_b64: str) -> None:
    respx.post(RPC_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "method": "signMessage",
                "data": {"signature": signature_b64, "encoding": "base64"},
            },
        )
    )


async def initialized_signer(
    keypair: Keypair, authorization_context: PrivyAuthorizationContext | None = None
) -> PrivySigner:
    mock_wallet_response(str(keypair.pubkey()))
    signer = make_signer(authorization_context)
    await signer.init()
    return signer


def authorization_request(body: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "method": "POST",
        "url": "https://api.privy.test/wallets/test-wallet-id/rpc",
        "body": body,
        "headers": {
            "privy-app-id": "test-app-id",
            "privy-request-expiry": "1900000",
        },
    }


def test_formats_empty_authorization_request_bodies_canonically() -> None:
    payload = format_authorization_signature_payload(authorization_request({}))
    assert payload.decode() == (
        '{"body":"","headers":{"privy-app-id":"test-app-id",'
        '"privy-request-expiry":"1900000"},"method":"POST",'
        '"url":"https://api.privy.test/wallets/test-wallet-id/rpc","version":1}'
    )


def test_generates_base64_der_authorization_signatures() -> None:
    request = authorization_request(
        {
            "chain_type": "solana",
            "method": "signMessage",
            "params": {"encoding": "base64", "message": "AQIDBA=="},
        }
    )
    context = PrivyAuthorizationContext(
        authorization_private_keys=[f"wallet-auth:{TEST_P256_PKCS8_BASE64}"]
    )

    signatures = generate_authorization_signatures(request, context)

    payload = format_authorization_signature_payload(request)
    private_key = load_pem_private_key(TEST_P256_PKCS8_PEM.encode(), password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    private_key.public_key().verify(
        base64.b64decode(signatures[0]), payload, ec.ECDSA(hashes.SHA256())
    )


def test_preserves_signature_order() -> None:
    request = authorization_request({"method": "signMessage"})
    context = PrivyAuthorizationContext(
        signatures=["provided"], sign_fns=[lambda _payload: "sign-fn"]
    )
    assert generate_authorization_signatures(request, context) == ["provided", "sign-fn"]


@pytest.mark.parametrize(
    "invalid_key",
    [
        "wallet-auth:not-secret-but-sensitive",
        "-----BEGIN PRIVATE KEY-----\nnot-secret-but-sensitive\n-----END PRIVATE KEY-----",
        base64.b64encode(b"not-secret-but-sensitive").decode(),
    ],
)
def test_invalid_authorization_keys_never_leak(invalid_key: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        _parse_p256_private_key(invalid_key)
    error = excinfo.value
    assert error.code == SignerErrorCode.INVALID_PRIVATE_KEY
    for channel in (str(error), repr(error), repr(error.args)):
        assert "not-secret-but-sensitive" not in channel


@respx.mock
async def test_init_resolves_wallet_pubkey() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()
    request = respx.calls.last.request
    expected = base64.b64encode(f"{APP_ID}:{APP_SECRET}".encode()).decode()
    assert request.headers["Authorization"] == f"Basic {expected}"
    assert request.headers["privy-app-id"] == APP_ID


@respx.mock
async def test_init_rejects_non_solana_wallet() -> None:
    mock_wallet_response("0xabc", chain_type="ethereum")
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


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


def test_uninitialized_signer_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        _ = signer.pubkey
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


async def test_uninitialized_sign_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


async def test_uninitialized_is_available_false() -> None:
    assert not await make_signer().is_available()


@respx.mock
async def test_sign_message_success() -> None:
    keypair = Keypair()
    message = b"privy-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_response(base64.b64encode(bytes(signature)).decode())

    result = await signer.sign_message(message)

    assert result == signature
    request = respx.calls.last.request
    assert "privy-authorization-signature" not in request.headers
    parsed = json.loads(request.content)
    assert parsed == {
        "method": "signMessage",
        "chain_type": "solana",
        "params": {"message": base64.b64encode(message).decode(), "encoding": "base64"},
    }


@respx.mock
async def test_sign_message_with_authorization_context() -> None:
    keypair = Keypair()
    message = b"privy-message"
    signature = keypair.sign_message(message)
    context = PrivyAuthorizationContext(
        authorization_private_keys=[f"wallet-auth:{TEST_P256_PKCS8_BASE64}"]
    )
    signer = await initialized_signer(keypair, context)
    mock_sign_response(base64.b64encode(bytes(signature)).decode())

    result = await signer.sign_message(message)

    assert result == signature
    request = respx.calls.last.request
    expiry = request.headers["privy-request-expiry"]
    payload = format_authorization_signature_payload(
        {
            "version": 1,
            "method": "POST",
            "url": RPC_URL,
            "body": json.loads(request.content),
            "headers": {"privy-app-id": APP_ID, "privy-request-expiry": expiry},
        }
    )
    private_key = load_pem_private_key(TEST_P256_PKCS8_PEM.encode(), password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    private_key.public_key().verify(
        base64.b64decode(request.headers["privy-authorization-signature"]),
        payload,
        ec.ECDSA(hashes.SHA256()),
    )


@respx.mock
async def test_sign_message_omits_expiry_when_disabled() -> None:
    keypair = Keypair()
    message = b"privy-message"
    signature = keypair.sign_message(message)
    context = PrivyAuthorizationContext(
        authorization_private_keys=[f"wallet-auth:{TEST_P256_PKCS8_BASE64}"]
    )
    mock_wallet_response(str(keypair.pubkey()))
    signer = make_signer(context, authorization_request_expiry_ms=None)
    await signer.init()
    mock_sign_response(base64.b64encode(bytes(signature)).decode())

    await signer.sign_message(message)

    request = respx.calls.last.request
    assert "privy-request-expiry" not in request.headers
    assert "privy-authorization-signature" in request.headers


@respx.mock
async def test_empty_authorization_context_is_config_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, PrivyAuthorizationContext())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_response("!!!not-base64!!!")
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    keypair = Keypair()
    other = Keypair()
    message = b"privy-message"
    signer = await initialized_signer(keypair)
    mock_sign_response(base64.b64encode(bytes(other.sign_message(message))).decode())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(RPC_URL).mock(return_value=httpx.Response(500, json={"error": "boom"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())
    mock_sign_response(base64.b64encode(bytes(signature)).decode())

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_is_available_true_when_wallet_matches() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert await signer.is_available()


@respx.mock
async def test_is_available_false_when_wallet_changed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_wallet_response(str(Keypair().pubkey()))
    assert not await signer.is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(WALLET_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_privy_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_wallet_response(str(keypair.pubkey()))
    signer = await create_privy_signer(
        PrivySignerConfig(
            app_id=APP_ID,
            app_secret=APP_SECRET,
            wallet_id=WALLET_ID,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


def test_reprs_never_contain_app_secret() -> None:
    config = PrivySignerConfig(
        app_id=APP_ID, app_secret=APP_SECRET, wallet_id=WALLET_ID, api_base_url=API_BASE_URL
    )
    signer = make_signer()
    assert APP_SECRET not in repr(config)
    assert APP_SECRET not in repr(signer)
    assert repr(signer) == "PrivySigner(pubkey=None)"


def test_non_https_base_url_rejected() -> None:
    with pytest.raises(SignerError) as excinfo:
        PrivySigner(
            PrivySignerConfig(
                app_id=APP_ID,
                app_secret=APP_SECRET,
                wallet_id=WALLET_ID,
                api_base_url="http://privy.example.com",
            )
        )
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR
