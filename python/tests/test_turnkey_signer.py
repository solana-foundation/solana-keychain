import base64
import json
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from solders.keypair import Keypair

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.turnkey import TurnkeySigner, TurnkeySignerConfig, create_turnkey_signer
from tests.util import create_test_transaction

API_BASE_URL = "https://turnkey.example.com"
SIGN_URL = f"{API_BASE_URL}/public/v1/submit/sign_raw_payload"
WHOAMI_URL = f"{API_BASE_URL}/public/v1/query/whoami"
ORGANIZATION_ID = "test-org-id"
PRIVATE_KEY_ID = "test-key-id"


def make_api_keys() -> tuple[str, str, ec.EllipticCurvePublicKey]:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    private_hex = signing_key.private_numbers().private_value.to_bytes(32, "big").hex()
    public_key = signing_key.public_key()
    public_hex = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
    return public_hex, private_hex, public_key


def make_signer(
    pubkey: str,
    api_public_key: str | None = None,
    api_private_key: str | None = None,
) -> TurnkeySigner:
    if api_public_key is None or api_private_key is None:
        api_public_key, api_private_key, _ = make_api_keys()
    return TurnkeySigner(
        TurnkeySignerConfig(
            api_public_key=api_public_key,
            api_private_key=api_private_key,
            organization_id=ORGANIZATION_ID,
            private_key_id=PRIVATE_KEY_ID,
            public_key=pubkey,
            api_base_url=API_BASE_URL,
        )
    )


def mock_sign_response(r_hex: str, s_hex: str) -> None:
    respx.post(SIGN_URL).mock(
        return_value=httpx.Response(
            200,
            json={"activity": {"result": {"signRawPayloadResult": {"r": r_hex, "s": s_hex}}}},
        )
    )


@pytest.mark.parametrize("invalid", ["not-a-valid-pubkey", ""])
def test_invalid_pubkey_rejected(invalid: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(invalid)
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_non_https_base_url_rejected() -> None:
    keypair = Keypair()
    api_public_key, api_private_key, _ = make_api_keys()
    with pytest.raises(SignerError) as excinfo:
        TurnkeySigner(
            TurnkeySignerConfig(
                api_public_key=api_public_key,
                api_private_key=api_private_key,
                organization_id=ORGANIZATION_ID,
                private_key_id=PRIVATE_KEY_ID,
                public_key=str(keypair.pubkey()),
                api_base_url="http://turnkey.example.com",
            )
        )
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_reprs_never_contain_api_private_key() -> None:
    keypair = Keypair()
    api_public_key, api_private_key, _ = make_api_keys()
    config = TurnkeySignerConfig(
        api_public_key=api_public_key,
        api_private_key=api_private_key,
        organization_id=ORGANIZATION_ID,
        private_key_id=PRIVATE_KEY_ID,
        public_key=str(keypair.pubkey()),
    )
    signer = TurnkeySigner(
        TurnkeySignerConfig(
            api_public_key=api_public_key,
            api_private_key=api_private_key,
            organization_id=ORGANIZATION_ID,
            private_key_id=PRIVATE_KEY_ID,
            public_key=str(keypair.pubkey()),
            api_base_url=API_BASE_URL,
        )
    )
    assert repr(signer) == f"TurnkeySigner(pubkey={keypair.pubkey()})"
    assert api_private_key not in repr(config)
    assert api_private_key not in repr(signer)


@respx.mock
async def test_sign_message_success_with_stamp_and_body_assertions() -> None:
    keypair = Keypair()
    api_public_key, api_private_key, verifying_key = make_api_keys()
    message = b"test message"
    signature = keypair.sign_message(message)
    sig_bytes = bytes(signature)
    mock_sign_response(sig_bytes[:32].hex(), sig_bytes[32:].hex())

    signer = make_signer(str(keypair.pubkey()), api_public_key, api_private_key)
    result = await signer.sign_message(message)

    assert result == signature

    request = respx.calls.last.request
    body = request.content
    parsed = json.loads(body)
    assert parsed["type"] == "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
    assert parsed["organizationId"] == ORGANIZATION_ID
    assert parsed["parameters"] == {
        "signWith": PRIVATE_KEY_ID,
        "payload": message.hex(),
        "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
        "hashFunction": "HASH_FUNCTION_NOT_APPLICABLE",
    }

    stamp_raw = request.headers["X-Stamp"]
    padded = stamp_raw + "=" * (-len(stamp_raw) % 4)
    stamp = json.loads(base64.urlsafe_b64decode(padded))
    assert stamp["public_key"] == api_public_key
    assert stamp["scheme"] == "SIGNATURE_SCHEME_TK_API_P256"
    verifying_key.verify(bytes.fromhex(stamp["signature"]), body, ec.ECDSA(hashes.SHA256()))


@respx.mock
async def test_sign_message_left_pads_trimmed_components() -> None:
    keypair = Keypair()
    message = None
    signature = None
    for i in range(100_000):
        candidate = f"padding-{i}".encode()
        sig = keypair.sign_message(candidate)
        if bytes(sig)[0] == 0:
            message, signature = candidate, sig
            break
    assert message is not None and signature is not None

    sig_bytes = bytes(signature)
    trimmed_r = sig_bytes[:32].lstrip(b"\x00")
    mock_sign_response(trimmed_r.hex(), sig_bytes[32:].hex())

    signer = make_signer(str(keypair.pubkey()))
    result = await signer.sign_message(message)

    assert result == signature


@respx.mock
async def test_sign_message_rejects_oversized_component() -> None:
    keypair = Keypair()
    mock_sign_response("00" * 33, "00" * 32)
    signer = make_signer(str(keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_rejects_undecodable_component() -> None:
    keypair = Keypair()
    mock_sign_response("not-hex", "00" * 32)
    signer = make_signer(str(keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_missing_result() -> None:
    keypair = Keypair()
    respx.post(SIGN_URL).mock(return_value=httpx.Response(200, json={"activity": {}}))
    signer = make_signer(str(keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    signing_keypair = Keypair()
    other_keypair = Keypair()
    message = b"test message"
    sig_bytes = bytes(signing_keypair.sign_message(message))
    mock_sign_response(sig_bytes[:32].hex(), sig_bytes[32:].hex())

    signer = make_signer(str(other_keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_api_error() -> None:
    keypair = Keypair()
    respx.post(SIGN_URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    signer = make_signer(str(keypair.pubkey()))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_sign_message_invalid_api_private_key_hex() -> None:
    keypair = Keypair()
    api_public_key, _, _ = make_api_keys()
    signer = make_signer(str(keypair.pubkey()), api_public_key, "not-hex")
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


async def test_sign_message_wrong_length_api_private_key() -> None:
    keypair = Keypair()
    api_public_key, _, _ = make_api_keys()
    signer = make_signer(str(keypair.pubkey()), api_public_key, "ab" * 16)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())
    sig_bytes = bytes(signature)
    mock_sign_response(sig_bytes[:32].hex(), sig_bytes[32:].hex())

    signer = make_signer(str(keypair.pubkey()))
    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_is_available_success() -> None:
    keypair = Keypair()
    respx.post(WHOAMI_URL).mock(
        return_value=httpx.Response(200, json={"organizationId": ORGANIZATION_ID})
    )
    signer = make_signer(str(keypair.pubkey()))

    assert await signer.is_available()
    parsed: dict[str, Any] = json.loads(respx.calls.last.request.content)
    assert parsed == {"organizationId": ORGANIZATION_ID}


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    respx.post(WHOAMI_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    signer = make_signer(str(keypair.pubkey()))
    assert not await signer.is_available()


async def test_create_turnkey_signer_factory() -> None:
    keypair = Keypair()
    api_public_key, api_private_key, _ = make_api_keys()
    signer = await create_turnkey_signer(
        TurnkeySignerConfig(
            api_public_key=api_public_key,
            api_private_key=api_private_key,
            organization_id=ORGANIZATION_ID,
            private_key_id=PRIVATE_KEY_ID,
            public_key=str(keypair.pubkey()),
        )
    )
    assert signer.pubkey == keypair.pubkey()
