import hashlib
import json
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from solders.keypair import Keypair
from solders.signature import Signature

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import serialize_transaction, signed_message_bytes
from solana_keychain.fireblocks import (
    FireblocksSigner,
    FireblocksSignerConfig,
    create_fireblocks_signer,
)
from solana_keychain.fireblocks.jwt import (
    JWT_SKEW_LEEWAY_SECONDS,
    JWT_TTL_SECONDS,
    create_jwt,
    parse_signing_key,
)
from tests.util import create_test_transaction, create_test_v1_transaction

API_BASE_URL = "https://fireblocks.example.com"
API_KEY = "test-api-key"
VAULT_ACCOUNT_ID = "7"
ADDRESSES_URL = f"{API_BASE_URL}/v1/vault/accounts/{VAULT_ACCOUNT_ID}/SOL/addresses_paginated"
TRANSACTIONS_URL = f"{API_BASE_URL}/v1/transactions"
ACCOUNT_URL = f"{API_BASE_URL}/v1/vault/accounts/{VAULT_ACCOUNT_ID}"

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIVATE_PEM = _RSA_KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
RSA_PUBLIC_KEY = _RSA_KEY.public_key()


def make_signer(**overrides: Any) -> FireblocksSigner:
    config = FireblocksSignerConfig(
        api_key=API_KEY,
        private_key_pem=overrides.pop("private_key_pem", RSA_PRIVATE_PEM),
        vault_account_id=VAULT_ACCOUNT_ID,
        api_base_url=API_BASE_URL,
        poll_interval_ms=0,
        **overrides,
    )
    return FireblocksSigner(config)


def mock_addresses_response(address: str) -> None:
    respx.get(ADDRESSES_URL).mock(
        return_value=httpx.Response(200, json={"addresses": [{"address": address}]})
    )


def transaction_response(
    status: str, full_sig: str | None = None, tx_id: str = "tx-1"
) -> dict[str, Any]:
    body: dict[str, Any] = {"id": tx_id, "status": status}
    if full_sig is not None:
        body["signedMessages"] = [{"signature": {"fullSig": full_sig}}]
    return body


def mock_sign_flow(full_sig: str, intermediate_statuses: list[str] | None = None) -> None:
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    poll_responses = [
        httpx.Response(200, json=transaction_response(status))
        for status in (intermediate_statuses or [])
    ]
    poll_responses.append(
        httpx.Response(200, json=transaction_response("COMPLETED", full_sig=full_sig))
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(side_effect=poll_responses)


async def initialized_signer(keypair: Keypair, **overrides: Any) -> FireblocksSigner:
    mock_addresses_response(str(keypair.pubkey()))
    signer = make_signer(**overrides)
    await signer.init()
    return signer


def decode_bearer_claims(request: httpx.Request) -> dict[str, Any]:
    token = request.headers["Authorization"].removeprefix("Bearer ")
    return pyjwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"])


def test_create_jwt_claims_shape() -> None:
    signing_key = parse_signing_key(RSA_PRIVATE_PEM)
    body = '{"test": "body"}'
    token = create_jwt(API_KEY, signing_key, "/v1/transactions", body)

    claims = pyjwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"])
    assert claims["uri"] == "/v1/transactions"
    assert claims["sub"] == API_KEY
    assert claims["iat"] == claims["nbf"]
    assert claims["exp"] - claims["iat"] == JWT_TTL_SECONDS + JWT_SKEW_LEEWAY_SECONDS
    assert claims["bodyHash"] == hashlib.sha256(body.encode()).hexdigest()
    assert claims["nonce"]


def test_parse_signing_key_invalid() -> None:
    with pytest.raises(SignerError) as excinfo:
        parse_signing_key("invalid-key")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def mock_program_call_flow(poll_body: dict[str, Any]) -> None:
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(return_value=httpx.Response(200, json=poll_body))


@respx.mock
async def test_program_call_requests_sign_only_and_uses_signed_messages() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    program_call_data = serialize_transaction(transaction)
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_program_call_flow(
        {
            "id": "tx-1",
            "status": "SIGNED",
            "signedMessages": [{"signature": {"fullSig": bytes(signature).hex()}}],
        }
    )

    result = await signer.sign_transaction(transaction)

    assert result.signature == signature
    request_body = json.loads(respx.calls[1].request.content)
    assert request_body["operation"] == "PROGRAM_CALL"
    assert request_body["extraParameters"] == {
        "programCallData": program_call_data,
        "signOnly": True,
        "useDurableNonce": False,
    }


@respx.mock
async def test_program_call_accepts_signature_carried_as_tx_hash() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_program_call_flow({"id": "tx-1", "status": "SIGNED", "txHash": str(signature)})

    result = await signer.sign_transaction(transaction)

    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_program_call_rejects_tx_hash_that_is_not_the_vault_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    foreign_signature = Keypair().sign_message(signed_message_bytes(transaction.message))
    mock_program_call_flow({"id": "tx-1", "status": "SIGNED", "txHash": str(foreign_signature)})

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert all(signature == Signature.default() for signature in transaction.signatures)


@respx.mock
async def test_program_call_broadcast_despite_sign_only_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_program_call_flow({"id": "tx-1", "status": "BROADCASTING", "txHash": str(signature)})

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_program_call_polling_timeout_keeps_the_transaction_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True, max_poll_attempts=3)
    transaction = create_test_transaction(keypair.pubkey())
    mock_program_call_flow({"id": "tx-1", "status": "SUBMITTED"})

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_program_call_poll_failure_keeps_the_transaction_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(return_value=httpx.Response(503, text="unavailable"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_program_call_create_5xx_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(503, text="unavailable"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED


@respx.mock
async def test_program_call_create_5xx_keeps_a_transaction_id_from_the_body() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(503, json={"id": "tx-accepted"}))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-accepted"


@respx.mock
async def test_program_call_create_4xx_stays_a_rejection() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(400, text="bad request"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_program_call_accepted_create_without_an_id_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"status": "SUBMITTED"})
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED


@respx.mock
async def test_raw_create_5xx_stays_a_plain_failure() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(503, text="unavailable"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")

    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_program_call_rejects_v1_message_before_creating_a_transaction() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, use_program_call=True)
    transaction = create_test_v1_transaction(keypair.pubkey())

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)

    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert len(respx.calls) == 1


@respx.mock
async def test_init_resolves_vault_pubkey_with_stamped_jwt() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()

    request = respx.calls.last.request
    assert request.headers["X-API-Key"] == API_KEY
    claims = decode_bearer_claims(request)
    assert claims["uri"] == f"/v1/vault/accounts/{VAULT_ACCOUNT_ID}/SOL/addresses_paginated"
    assert claims["bodyHash"] == hashlib.sha256(b"").hexdigest()


@respx.mock
async def test_init_rejects_empty_addresses() -> None:
    respx.get(ADDRESSES_URL).mock(return_value=httpx.Response(200, json={"addresses": []}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_selects_address_for_configured_asset() -> None:
    wanted = str(Keypair().pubkey())
    respx.get(ADDRESSES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "addresses": [
                    {"address": str(Keypair().pubkey()), "assetId": "SOL_TEST"},
                    {"address": wanted, "assetId": "SOL"},
                ]
            },
        )
    )
    signer = make_signer()
    await signer.init()
    assert str(signer.pubkey) == wanted


@respx.mock
async def test_init_selects_address_for_custom_asset_id() -> None:
    devnet = str(Keypair().pubkey())
    respx.get(
        f"{API_BASE_URL}/v1/vault/accounts/{VAULT_ACCOUNT_ID}/SOL_TEST/addresses_paginated"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "addresses": [
                    {"address": str(Keypair().pubkey()), "assetId": "SOL"},
                    {"address": devnet, "assetId": "SOL_TEST"},
                ]
            },
        )
    )
    signer = make_signer(asset_id="SOL_TEST")
    await signer.init()
    assert str(signer.pubkey) == devnet


@respx.mock
async def test_init_rejects_ambiguous_addresses() -> None:
    respx.get(ADDRESSES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "addresses": [
                    {"address": str(Keypair().pubkey()), "assetId": "SOL"},
                    {"address": str(Keypair().pubkey()), "assetId": "SOL"},
                ]
            },
        )
    )
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_rejects_no_address_for_configured_asset() -> None:
    respx.get(ADDRESSES_URL).mock(
        return_value=httpx.Response(
            200,
            json={"addresses": [{"address": str(Keypair().pubkey()), "assetId": "SOL_TEST"}]},
        )
    )
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_accepts_duplicate_address_entries() -> None:
    wanted = str(Keypair().pubkey())
    respx.get(ADDRESSES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "addresses": [
                    {"address": wanted, "assetId": "SOL"},
                    {"address": wanted, "assetId": "SOL"},
                ]
            },
        )
    )
    signer = make_signer()
    await signer.init()
    assert str(signer.pubkey) == wanted


@respx.mock
async def test_init_rejects_invalid_address() -> None:
    mock_addresses_response("not-a-pubkey")
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_api_error() -> None:
    respx.get(ADDRESSES_URL).mock(return_value=httpx.Response(401, json={"error": "denied"}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


async def test_invalid_rsa_key_surfaces_on_use() -> None:
    signer = make_signer(private_key_pem="not-a-pem")
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


async def test_uninitialized_sign_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_message_success_with_polling() -> None:
    keypair = Keypair()
    message = b"fireblocks-message"
    signature = keypair.sign_message(message)
    signer = await initialized_signer(keypair)
    mock_sign_flow(bytes(signature).hex(), intermediate_statuses=["SUBMITTED", "SIGNING"])

    result = await signer.sign_message(message)

    assert result == signature
    create_request = respx.calls[1].request
    body = json.loads(create_request.content)
    assert body == {
        "assetId": "SOL",
        "operation": "RAW",
        "source": {"type": "VAULT_ACCOUNT", "id": VAULT_ACCOUNT_ID},
        "extraParameters": {"rawMessageData": {"messages": [{"content": message.hex()}]}},
    }
    claims = decode_bearer_claims(create_request)
    assert claims["uri"] == "/v1/transactions"
    assert claims["bodyHash"] == hashlib.sha256(create_request.content).hexdigest()


@respx.mock
@pytest.mark.parametrize("status", ["FAILED", "CANCELLED", "REJECTED", "BLOCKED"])
async def test_sign_message_terminal_failure_status(status: str) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(200, json=transaction_response(status))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_polling_timeout() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, max_poll_attempts=3)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(200, json=transaction_response("SUBMITTED"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_message_missing_signed_messages() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "tx-1", "status": "SUBMITTED"})
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(200, json=transaction_response("COMPLETED"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_flow("zz" * 64)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    mock_sign_flow("ab" * 32)
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_signature_verification_failure() -> None:
    keypair = Keypair()
    other = Keypair()
    message = b"fireblocks-message"
    signer = await initialized_signer(keypair)
    mock_sign_flow(bytes(other.sign_message(message)).hex())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_success() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_sign_flow(bytes(signature).hex())

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert list(transaction.signatures) == [signature]


async def test_uninitialized_is_available_false() -> None:
    assert not await make_signer().is_available()


@respx.mock
async def test_is_available_success() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(ACCOUNT_URL).mock(return_value=httpx.Response(200, json={"id": VAULT_ACCOUNT_ID}))
    assert await signer.is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.get(ACCOUNT_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_fireblocks_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_addresses_response(str(keypair.pubkey()))
    signer = await create_fireblocks_signer(
        FireblocksSignerConfig(
            api_key=API_KEY,
            private_key_pem=RSA_PRIVATE_PEM,
            vault_account_id=VAULT_ACCOUNT_ID,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


def test_reprs_never_contain_secrets() -> None:
    config = FireblocksSignerConfig(
        api_key=API_KEY,
        private_key_pem=RSA_PRIVATE_PEM,
        vault_account_id=VAULT_ACCOUNT_ID,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer()
    for text in (repr(config), repr(signer)):
        assert API_KEY not in text
        assert "PRIVATE KEY" not in text
