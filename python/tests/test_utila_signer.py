import base64
import json
import time
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
from solders.transaction import Transaction

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.utila import UtilaSigner, UtilaSignerConfig, create_utila_signer
from tests.util import create_test_transaction

API_BASE_URL = "https://utila.example.com"
EMAIL = "service-account@vault.utilaserviceaccount.io"
VAULT_ID = "vault-test"
WALLET_ID = "wallet-test"
NETWORK = "networks/solana-devnet"

WALLET_URL = f"{API_BASE_URL}/v2/vaults/{VAULT_ID}/wallets/{WALLET_ID}"
INITIATE_URL = f"{API_BASE_URL}/v2/vaults/{VAULT_ID}/transactions:initiate"
GET_TX_URL = f"{API_BASE_URL}/v2/vaults/{VAULT_ID}/transactions/tx-1"

_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIVATE_PEM = _RSA_KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
RSA_PUBLIC_KEY = _RSA_KEY.public_key()


def make_signer(**overrides: Any) -> UtilaSigner:
    config = UtilaSignerConfig(
        service_account_email=overrides.pop("service_account_email", EMAIL),
        service_account_private_key_pem=overrides.pop(
            "service_account_private_key_pem", RSA_PRIVATE_PEM
        ),
        vault_id=overrides.pop("vault_id", VAULT_ID),
        wallet_id=overrides.pop("wallet_id", WALLET_ID),
        network=overrides.pop("network", NETWORK),
        api_base_url=overrides.pop("api_base_url", API_BASE_URL),
        poll_interval_ms=overrides.pop("poll_interval_ms", 1),
        **overrides,
    )
    return UtilaSigner(config)


def mock_wallet(address: str | None) -> None:
    wallet: dict[str, Any] = {"name": f"vaults/{VAULT_ID}/wallets/{WALLET_ID}"}
    if address is not None:
        wallet["solanaDetails"] = {"address": address}
    respx.get(WALLET_URL).mock(return_value=httpx.Response(200, json={"wallet": wallet}))


def utila_transaction(state: str, raw_transaction: str | None = None) -> dict[str, Any]:
    transaction: dict[str, Any] = {
        "name": f"vaults/{VAULT_ID}/transactions/tx-1",
        "state": state,
    }
    if raw_transaction is not None:
        transaction["solanaTransaction"] = {"rawTransaction": raw_transaction}
    return transaction


def signed_raw_transaction(keypair: Keypair, transaction: Transaction) -> str:
    signed = Transaction.from_bytes(bytes(transaction))
    signed.signatures = [keypair.sign_message(transaction.message_data())]
    return base64.b64encode(bytes(signed)).decode()


async def initialized_signer(keypair: Keypair, **overrides: Any) -> UtilaSigner:
    mock_wallet(str(keypair.pubkey()))
    signer = make_signer(**overrides)
    await signer.init()
    return signer


@pytest.mark.parametrize(
    "overrides",
    [
        {"service_account_email": "  "},
        {"service_account_private_key_pem": ""},
        {"vault_id": ""},
        {"wallet_id": ""},
        {"network": ""},
        {"poll_interval_ms": 0},
        {"max_poll_attempts": 0},
        {"api_base_url": "http://utila.example.com"},
    ],
)
def test_invalid_config_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(**overrides)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_invalid_rsa_key_rejected_at_construction() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(service_account_private_key_pem="not-a-pem")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_pem_with_escaped_newlines_accepted() -> None:
    # Env-var PEMs arrive with literal \n escapes; construction must parse them.
    escaped = RSA_PRIVATE_PEM.replace("\n", "\\n")
    make_signer(service_account_private_key_pem=escaped)


@respx.mock
async def test_resource_name_prefixes_are_trimmed() -> None:
    keypair = Keypair()
    mock_wallet(str(keypair.pubkey()))
    signer = make_signer(
        vault_id=f"vaults/{VAULT_ID}",
        wallet_id=f"vaults/{VAULT_ID}/wallets/{WALLET_ID}",
    )
    await signer.init()
    assert signer.pubkey == keypair.pubkey()
    assert str(respx.calls.last.request.url) == WALLET_URL


@respx.mock
async def test_access_token_claims() -> None:
    await initialized_signer(Keypair())
    token = respx.calls.last.request.headers["Authorization"].removeprefix("Bearer ")
    claims = pyjwt.decode(
        token, RSA_PUBLIC_KEY, algorithms=["RS256"], audience="https://api.utila.io/"
    )
    assert claims["sub"] == EMAIL
    assert claims["aud"] == "https://api.utila.io/"
    assert 0 < claims["exp"] - int(time.time()) <= 55 * 60


@respx.mock
async def test_init_rejects_missing_solana_details() -> None:
    mock_wallet(None)
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_rejects_invalid_address() -> None:
    mock_wallet("not-a-pubkey")
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


async def test_sign_message_is_unsupported() -> None:
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


async def test_uninitialized_sign_transaction_raises_not_initialized() -> None:
    with pytest.raises(SignerError) as excinfo:
        await make_signer().sign_transaction(create_test_transaction(Keypair().pubkey()))
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_transaction_success_with_polling() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    unsigned_b64 = base64.b64encode(bytes(transaction)).decode()
    expected_signature = keypair.sign_message(transaction.message_data())

    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200, json={"transaction": utila_transaction("AWAITING_SIGNATURE")}
        )
    )
    respx.get(f"{GET_TX_URL}?view=FULL").mock(
        return_value=httpx.Response(
            200,
            json={
                "transaction": utila_transaction(
                    "SIGNED", raw_transaction=signed_raw_transaction(keypair, transaction)
                )
            },
        )
    )

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == expected_signature
    assert list(transaction.signatures) == [expected_signature]

    initiate_body = json.loads(respx.calls[1].request.content)
    assert initiate_body == {
        "details": {
            "solanaSerializedTransaction": {
                "network": NETWORK,
                "rawTransaction": unsigned_b64,
                "publish": False,
                "replaceBlockhash": False,
                "tryReplaceBlockhash": False,
            }
        },
        "designatedSigners": [f"users/{EMAIL}"],
    }


@respx.mock
async def test_custom_designated_signers() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, designated_signers=["users/other@example.com"])
    transaction = create_test_transaction(keypair.pubkey())
    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "transaction": utila_transaction(
                    "SIGNED", raw_transaction=signed_raw_transaction(keypair, transaction)
                )
            },
        )
    )

    await signer.sign_transaction(transaction)

    initiate_body = json.loads(respx.calls[1].request.content)
    assert initiate_body["designatedSigners"] == ["users/other@example.com"]


@respx.mock
@pytest.mark.parametrize("state", ["FAILED", "DECLINED", "CANCELED", "EXPIRED", "DROPPED"])
async def test_sign_transaction_terminal_failure(state: str) -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(200, json={"transaction": utila_transaction(state)})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_polling_timeout() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, max_poll_attempts=2)
    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200, json={"transaction": utila_transaction("AWAITING_APPROVAL")}
        )
    )
    respx.get(f"{GET_TX_URL}?view=FULL").mock(
        return_value=httpx.Response(
            200, json={"transaction": utila_transaction("AWAITING_APPROVAL")}
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_transaction_missing_raw_transaction() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(200, json={"transaction": utila_transaction("SIGNED")})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_rewritten_message_bytes_are_rejected() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    rewritten = create_test_transaction(keypair.pubkey())
    assert rewritten.message_data() != transaction.message_data()

    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "transaction": utila_transaction(
                    "SIGNED", raw_transaction=signed_raw_transaction(keypair, rewritten)
                )
            },
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_unsigned_raw_transaction_is_rejected() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    unsigned_b64 = base64.b64encode(bytes(transaction)).decode()

    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200,
            json={"transaction": utila_transaction("SIGNED", raw_transaction=unsigned_b64)},
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_undecodable_raw_transaction() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(INITIATE_URL).mock(
        return_value=httpx.Response(
            200,
            json={"transaction": utila_transaction("SIGNED", raw_transaction="!!!")},
        )
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_is_available_true_and_false() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    assert await signer.is_available()
    respx.get(WALLET_URL).mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
    assert not await signer.is_available()


@respx.mock
async def test_create_utila_signer_factory_initializes() -> None:
    keypair = Keypair()
    mock_wallet(str(keypair.pubkey()))
    signer = await create_utila_signer(
        UtilaSignerConfig(
            service_account_email=EMAIL,
            service_account_private_key_pem=RSA_PRIVATE_PEM,
            vault_id=VAULT_ID,
            wallet_id=WALLET_ID,
            network=NETWORK,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


def test_reprs_never_contain_private_key() -> None:
    config = UtilaSignerConfig(
        service_account_email=EMAIL,
        service_account_private_key_pem=RSA_PRIVATE_PEM,
        vault_id=VAULT_ID,
        wallet_id=WALLET_ID,
        network=NETWORK,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer()
    for text in (repr(config), repr(signer)):
        assert "PRIVATE KEY" not in text
