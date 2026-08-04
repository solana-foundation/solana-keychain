import base64
import json
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.dfns import DfnsSigner, DfnsSignerConfig, create_dfns_signer
from solana_keychain.dfns.auth import format_client_data, sign_challenge
from tests.util import create_test_transaction

API_BASE_URL = "https://dfns.example.com"
AUTH_TOKEN = "test-auth-token"
CRED_ID = "test-cred-id"
WALLET_ID = "test-wallet-id"
KEY_ID = "test-key-id"

WALLET_URL = f"{API_BASE_URL}/wallets/{WALLET_ID}"
ACTION_INIT_URL = f"{API_BASE_URL}/auth/action/init"
ACTION_URL = f"{API_BASE_URL}/auth/action"
SIGNATURES_URL = f"{API_BASE_URL}/keys/{KEY_ID}/signatures"

ED25519_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikUmifl1yiWd+IiYyoHBD\n"
    "-----END PRIVATE KEY-----"
)
P256_PKCS8_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNVGLQN9VkU26M2JG\n"
    "3hbSFACbGLXkQlB69ZxAhXGqf/mhRANCAATjr6H28PJiFSlRz9kfkzu9Fy6vt1uY\n"
    "9Egu4yP/e2qnDZ+SjpcQo1hpF6Cb1h6S1a2b7qi3IEEnh+d/vzlOHAaf\n"
    "-----END PRIVATE KEY-----"
)
P256_SEC1_PEM = (
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIGa93+PpxzDlIywW+Al/cpIAGzLKwGwIDWpgwrJ+ht9ZoAoGCCqGSM49\n"
    "AwEHoUQDQgAE0Mi+Kw78tyVMPAGb6a6Nwn/yiz65gKVBS+nT171vqgLzoHwf51iU\n"
    "TLWfftn3ZyCvKLzTN5pd1Up982TKelcbFw==\n"
    "-----END EC PRIVATE KEY-----"
)


def make_signer() -> DfnsSigner:
    return DfnsSigner(
        DfnsSignerConfig(
            auth_token=AUTH_TOKEN,
            cred_id=CRED_ID,
            private_key_pem=ED25519_PEM,
            wallet_id=WALLET_ID,
            api_base_url=API_BASE_URL,
        )
    )


def wallet_response(
    pubkey_hex: str,
    status: str = "Active",
    scheme: str = "EdDSA",
    curve: str = "ed25519",
) -> dict[str, Any]:
    return {
        "id": WALLET_ID,
        "status": status,
        "signingKey": {
            "id": KEY_ID,
            "scheme": scheme,
            "curve": curve,
            "publicKey": pubkey_hex,
        },
    }


def mock_wallet(keypair: Keypair, **overrides: str) -> None:
    respx.get(WALLET_URL).mock(
        return_value=httpx.Response(
            200, json=wallet_response(bytes(keypair.pubkey()).hex(), **overrides)
        )
    )


def mock_user_action_flow(challenge: str = "test-challenge") -> None:
    respx.post(ACTION_INIT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "challenge": challenge,
                "challengeIdentifier": "challenge-id-1",
                "allowCredentials": {"key": [{"id": CRED_ID}], "webauthn": []},
            },
        )
    )
    respx.post(ACTION_URL).mock(
        return_value=httpx.Response(200, json={"userAction": "user-action-token"})
    )


def mock_signature_response(signature: bytes, prefix: str = "") -> None:
    respx.post(SIGNATURES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "sig-1",
                "status": "Signed",
                "signature": {
                    "r": f"{prefix}{signature[:32].hex()}",
                    "s": f"{prefix}{signature[32:].hex()}",
                },
            },
        )
    )


async def initialized_signer(keypair: Keypair) -> DfnsSigner:
    mock_wallet(keypair)
    signer = make_signer()
    await signer.init()
    return signer


def test_sign_challenge_ed25519_is_raw_64_bytes() -> None:
    assert len(sign_challenge(ED25519_PEM, b"test challenge data")) == 64


@pytest.mark.parametrize("pem", [P256_PKCS8_PEM, P256_SEC1_PEM])
def test_sign_challenge_p256_is_der(pem: str) -> None:
    signature = sign_challenge(pem, b"test challenge data")
    assert 68 <= len(signature) <= 72
    assert signature[0] == 0x30


def test_sign_challenge_invalid_key() -> None:
    with pytest.raises(SignerError) as excinfo:
        sign_challenge("not-a-pem-key", b"test")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_client_data_bytes_are_exact() -> None:
    assert format_client_data("abc") == b'{"challenge":"abc","type":"key.get"}'


@respx.mock
async def test_init_resolves_signing_key() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()
    assert respx.calls.last.request.headers["Authorization"] == f"Bearer {AUTH_TOKEN}"


@respx.mock
@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "Archived"},
        {"scheme": "ECDSA"},
        {"curve": "secp256k1"},
    ],
)
async def test_init_rejects_unusable_wallet(overrides: dict[str, str]) -> None:
    mock_wallet(Keypair(), **overrides)
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
@pytest.mark.parametrize("pubkey_hex", ["not-hex", "abcd"])
async def test_init_rejects_bad_public_key(pubkey_hex: str) -> None:
    respx.get(WALLET_URL).mock(return_value=httpx.Response(200, json=wallet_response(pubkey_hex)))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_api_error() -> None:
    respx.get(WALLET_URL).mock(return_value=httpx.Response(401, json={"error": "denied"}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_uninitialized_sign_raises_not_initialized() -> None:
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_message_full_user_action_flow() -> None:
    keypair = Keypair()
    message = b"dfns-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    mock_signature_response(bytes(signature))

    result = await signer.sign_message(message)

    assert result == signature

    init_request = json.loads(respx.calls[1].request.content)
    expected_body = json.dumps(
        {"kind": "Message", "message": f"0x{message.hex()}"}, separators=(",", ":")
    )
    assert init_request == {
        "userActionPayload": expected_body,
        "userActionHttpMethod": "POST",
        "userActionHttpPath": f"/keys/{KEY_ID}/signatures",
        "userActionServerKind": "Api",
    }

    action_request = json.loads(respx.calls[2].request.content)
    assertion = action_request["firstFactor"]["credentialAssertion"]
    assert action_request["challengeIdentifier"] == "challenge-id-1"
    assert action_request["firstFactor"]["kind"] == "Key"
    assert assertion["credId"] == CRED_ID
    padded = assertion["clientData"] + "=" * (-len(assertion["clientData"]) % 4)
    client_data = base64.urlsafe_b64decode(padded)
    assert client_data == format_client_data("test-challenge")
    credential_key = load_pem_private_key(ED25519_PEM.encode(), password=None)
    signature_padded = assertion["signature"] + "=" * (-len(assertion["signature"]) % 4)
    credential_key.public_key().verify(  # type: ignore[union-attr, call-arg]
        base64.urlsafe_b64decode(signature_padded), client_data
    )

    sign_request = respx.calls[3].request
    assert sign_request.headers["x-dfns-useraction"] == "user-action-token"
    assert sign_request.content == expected_body.encode()


@respx.mock
async def test_sign_message_rejects_disallowed_credential() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(ACTION_INIT_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "challenge": "c",
                "challengeIdentifier": "ci",
                "allowCredentials": {"key": [{"id": "other-cred"}]},
            },
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_sign_message_accepts_0x_prefixed_components() -> None:
    keypair = Keypair()
    message = b"dfns-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    mock_signature_response(bytes(signature), prefix="0x")

    assert await signer.sign_message(message) == signature


@respx.mock
@pytest.mark.parametrize(
    ("status", "signature"),
    [
        ("Failed", None),
        ("Pending", None),
        ("Signed", None),
    ],
)
async def test_sign_message_bad_status_or_missing_components(
    status: str, signature: dict[str, str] | None
) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    respx.post(SIGNATURES_URL).mock(
        return_value=httpx.Response(
            200, json={"id": "sig-1", "status": status, "signature": signature}
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_undecodable_component() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    respx.post(SIGNATURES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "sig-1",
                "status": "Signed",
                "signature": {"r": "not-hex", "s": "00" * 32},
            },
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    respx.post(SIGNATURES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "sig-1",
                "status": "Signed",
                "signature": {"r": "00" * 16, "s": "00" * 16},
            },
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    keypair = Keypair()
    message = b"dfns-message"
    signer = await initialized_signer(keypair)
    mock_user_action_flow()
    mock_signature_response(bytes(Keypair().sign_message(message)))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())
    mock_user_action_flow()
    mock_signature_response(bytes(signature))

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]

    sign_request = json.loads(respx.calls[3].request.content)
    assert sign_request["kind"] == "Transaction"
    assert sign_request["blockchainKind"] == "Solana"
    assert sign_request["transaction"].startswith("0x")


@respx.mock
@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, True),
        ({"status": "Archived"}, False),
        ({"scheme": "ECDSA"}, False),
        ({"curve": "secp256k1"}, False),
    ],
)
async def test_is_available_gates_wallet_health(overrides: dict[str, str], expected: bool) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_wallet(keypair, **overrides)
    assert await signer.is_available() is expected


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(WALLET_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_dfns_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_wallet(keypair)
    signer = await create_dfns_signer(
        DfnsSignerConfig(
            auth_token=AUTH_TOKEN,
            cred_id=CRED_ID,
            private_key_pem=ED25519_PEM,
            wallet_id=WALLET_ID,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


def test_reprs_never_contain_secrets() -> None:
    config = DfnsSignerConfig(
        auth_token=AUTH_TOKEN,
        cred_id=CRED_ID,
        private_key_pem=ED25519_PEM,
        wallet_id=WALLET_ID,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer()
    for text in (repr(config), repr(signer)):
        assert AUTH_TOKEN not in text
        assert "PRIVATE KEY" not in text
