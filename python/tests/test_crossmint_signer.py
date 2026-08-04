import json
from typing import Any

import base58
import httpx
import pytest
import respx
from solders.keypair import Keypair
from solders.signature import Signature

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.crossmint import (
    CrossmintSigner,
    CrossmintSignerConfig,
    create_crossmint_signer,
)
from solana_keychain.crossmint.derive import derive_signing_key, parse_api_key
from tests.util import create_test_transaction

API_BASE_URL = "https://crossmint.example.com/api"
API_KEY = "sk_staging_" + base58.b58encode(b"project-123:nacl-sig").decode()
SIGNER_SECRET = "xmsk1_" + "ab" * 32
WALLET_LOCATOR = "email:user@test.com:solana"
ENCODED_LOCATOR = "email%3Auser%40test.com%3Asolana"
WALLET_URL = f"{API_BASE_URL}/2025-06-09/wallets/{ENCODED_LOCATOR}"
TRANSACTIONS_URL = f"{WALLET_URL}/transactions"


def make_signer(**overrides: Any) -> CrossmintSigner:
    config = CrossmintSignerConfig(
        api_key=overrides.pop("api_key", API_KEY),
        wallet_locator=overrides.pop("wallet_locator", WALLET_LOCATOR),
        api_base_url=overrides.pop("api_base_url", API_BASE_URL),
        poll_interval_ms=overrides.pop("poll_interval_ms", 1),
        **overrides,
    )
    return CrossmintSigner(config)


def mock_wallet(address: str, chain_type: str = "solana", wallet_type: str = "smart") -> None:
    respx.get(WALLET_URL).mock(
        return_value=httpx.Response(
            200, json={"chainType": chain_type, "type": wallet_type, "address": address}
        )
    )


async def initialized_signer(keypair: Keypair, **overrides: Any) -> CrossmintSigner:
    mock_wallet(str(keypair.pubkey()))
    signer = make_signer(**overrides)
    await signer.init()
    return signer


def signed_transaction_b58(keypair: Keypair, transaction: Any) -> str:
    from solders.transaction import Transaction

    signed = Transaction.from_bytes(bytes(transaction))
    signed.signatures = [keypair.sign_message(transaction.message_data())]
    return base58.b58encode(bytes(signed)).decode()


def tx_response(status: str, tx_id: str = "tx-1", **extra: Any) -> dict[str, Any]:
    return {"id": tx_id, "status": status, **extra}


def test_parse_api_key() -> None:
    assert parse_api_key(API_KEY) == ("project-123", "staging")
    with pytest.raises(SignerError) as excinfo:
        parse_api_key("sk_missing-data")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_derive_signing_key_is_deterministic_and_env_scoped() -> None:
    key_one = derive_signing_key(SIGNER_SECRET, API_KEY)
    key_two = derive_signing_key(SIGNER_SECRET, API_KEY)
    assert key_one.pubkey() == key_two.pubkey()

    production_key = API_KEY.replace("_staging_", "_production_")
    assert derive_signing_key(SIGNER_SECRET, production_key).pubkey() != key_one.pubkey()


@pytest.mark.parametrize(
    "secret",
    ["xmsk1_" + "ab" * 16, "xmsk1_" + "zz" * 32],
)
def test_derive_signing_key_rejects_bad_secret(secret: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        derive_signing_key(secret, API_KEY)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_signer_secret_default_locator() -> None:
    signer = make_signer(signer_secret=SIGNER_SECRET)
    derived = derive_signing_key(SIGNER_SECRET, API_KEY)
    assert signer._signer == f"server:{derived.pubkey()}"


@pytest.mark.parametrize(
    "overrides",
    [
        {"api_key": ""},
        {"wallet_locator": ""},
        {"api_base_url": "http://crossmint.example.com"},
        {"poll_interval_ms": 0},
        {"max_poll_attempts": 0},
    ],
)
def test_invalid_config_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(**overrides)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_resolves_wallet_with_encoded_locator() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert signer.pubkey == keypair.pubkey()
    request = respx.calls.last.request
    assert ENCODED_LOCATOR in str(request.url)
    assert request.headers["X-API-KEY"] == API_KEY


@respx.mock
@pytest.mark.parametrize(
    ("chain_type", "wallet_type"),
    [("ethereum", "smart"), ("solana", "custodial")],
)
async def test_init_rejects_unusable_wallet(chain_type: str, wallet_type: str) -> None:
    mock_wallet(str(Keypair().pubkey()), chain_type=chain_type, wallet_type=wallet_type)
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_accepts_mpc_wallet() -> None:
    keypair = Keypair()
    mock_wallet(str(keypair.pubkey()), wallet_type="MPC")
    signer = make_signer()
    await signer.init()
    assert signer.pubkey == keypair.pubkey()


@respx.mock
async def test_init_surfaces_api_error_message() -> None:
    respx.get(WALLET_URL).mock(
        return_value=httpx.Response(404, json={"message": "wallet not found"})
    )
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_init_missing_field_is_serialization_error() -> None:
    respx.get(WALLET_URL).mock(return_value=httpx.Response(200, json={"unexpected": True}))
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


async def test_sign_message_is_unsupported() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_uninitialized_sign_transaction_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(Keypair().pubkey()))
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_transaction_success_from_embedded_transaction() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    unsigned_bytes = bytes(transaction)
    expected_signature = keypair.sign_message(transaction.message_data())

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json=tx_response("pending")))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": signed_transaction_b58(keypair, transaction)},
            ),
        )
    )

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == expected_signature
    create_body = json.loads(respx.calls[1].request.content)
    assert "signer" not in create_body["params"]
    assert base58.b58decode(create_body["params"]["transaction"]) == unsigned_bytes


@respx.mock
async def test_sign_transaction_falls_back_to_tx_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(transaction.message_data())

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(signature)})
        )
    )

    result = await signer.sign_transaction(transaction)
    assert result.signature == signature


@respx.mock
async def test_sign_transaction_rejects_tx_id_for_different_bytes() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    other_signature = keypair.sign_message(b"different bytes")

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(other_signature)})
        )
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_failed_status() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json=tx_response("failed", error={"reason": "boom"}))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_polling_timeout() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, max_poll_attempts=2)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json=tx_response("pending")))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(200, json=tx_response("pending"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_awaiting_approval_without_signer_key_fails() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json=tx_response("awaiting-approval"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_awaiting_approval_signs_only_our_pending_entry() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, signer_secret=SIGNER_SECRET)
    transaction = create_test_transaction(keypair.pubkey())
    expected_signature = keypair.sign_message(transaction.message_data())
    delegated = derive_signing_key(SIGNER_SECRET, API_KEY)
    locator = f"server:{delegated.pubkey()}"
    challenge = b"approval-challenge-bytes"

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "awaiting-approval",
                approvals={
                    "pending": [
                        {"signer": {"locator": "other:approver"}, "message": "111"},
                        {
                            "signer": {"locator": locator},
                            "message": base58.b58encode(challenge).decode(),
                        },
                    ]
                },
            ),
        )
    )
    respx.post(f"{TRANSACTIONS_URL}/tx-1/approvals").mock(
        return_value=httpx.Response(200, json=tx_response("pending"))
    )
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": signed_transaction_b58(keypair, transaction)},
            ),
        )
    )

    result = await signer.sign_transaction(transaction)

    assert result.signature == expected_signature
    approval_body = json.loads(respx.calls[2].request.content)
    approval = approval_body["approvals"][0]
    assert approval["signer"] == locator
    approval_signature = Signature.from_bytes(base58.b58decode(approval["signature"]))
    assert approval_signature.verify(delegated.pubkey(), challenge)


@respx.mock
async def test_awaiting_approval_with_no_matching_entry_fails() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, signer_secret=SIGNER_SECRET)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "awaiting-approval",
                approvals={"pending": [{"signer": {"locator": "other:approver"}}]},
            ),
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_rewritten_transaction_signature_is_rejected() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())

    # The service returns a validly-signed transaction whose message differs from
    # the one the caller submitted (same payer, rewritten contents).
    rewritten = create_test_transaction(keypair.pubkey())
    assert rewritten.message_data() != transaction.message_data()
    rewritten.signatures = [keypair.sign_message(rewritten.message_data())]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_embedded_transaction_without_signer_signature_falls_through() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    unsigned_b58 = base58.b58encode(bytes(transaction)).decode()

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"transaction": unsigned_b58})
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_is_available_true_and_false() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert await signer.is_available()
    respx.get(WALLET_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_crossmint_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_wallet(str(keypair.pubkey()))
    signer = await create_crossmint_signer(
        CrossmintSignerConfig(
            api_key=API_KEY, wallet_locator=WALLET_LOCATOR, api_base_url=API_BASE_URL
        )
    )
    assert signer.pubkey == keypair.pubkey()


def test_reprs_never_contain_secrets() -> None:
    config = CrossmintSignerConfig(
        api_key=API_KEY,
        wallet_locator=WALLET_LOCATOR,
        signer_secret=SIGNER_SECRET,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer(signer_secret=SIGNER_SECRET)
    for text in (repr(config), repr(signer)):
        assert API_KEY not in text
        assert SIGNER_SECRET not in text
