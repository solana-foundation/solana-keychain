import asyncio
import base64
import hashlib
import json
import logging
import uuid
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain import SignerError, SignerErrorCode, create_keychain_signer
from solana_keychain.core import signed_message_bytes
from solana_keychain.core.transaction_util import idempotency_key_from_message
from solana_keychain.fordefi import (
    FordefiPushMode,
    FordefiRequestSigner,
    FordefiSigner,
    FordefiSignerConfig,
    PemRequestSigner,
    create_fordefi_signer,
)
from tests.util import (
    create_test_transaction,
    create_test_v0_transaction,
    create_test_v1_transaction,
    create_two_signer_transaction,
)

API_BASE_URL = "https://fordefi.example.com"
ACCESS_TOKEN = "test-access-token"
VAULT_ID = "test-vault-id"
VAULT_URL = f"{API_BASE_URL}/api/v1/vaults/{VAULT_ID}"
TRANSACTIONS_URL = f"{API_BASE_URL}/api/v1/transactions"

_EC_KEY = ec.generate_private_key(ec.SECP256R1())
EC_PRIVATE_PEM = _EC_KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
EC_PUBLIC_KEY = _EC_KEY.public_key()


def make_signer(keypair: Keypair, **overrides: Any) -> FordefiSigner:
    config = FordefiSignerConfig(
        access_token=overrides.pop("access_token", ACCESS_TOKEN),
        vault_id=overrides.pop("vault_id", VAULT_ID),
        public_key=overrides.pop("public_key", str(keypair.pubkey())),
        private_key_pem=overrides.pop("private_key_pem", EC_PRIVATE_PEM),
        api_base_url=overrides.pop("api_base_url", API_BASE_URL),
        poll_interval_ms=overrides.pop("poll_interval_ms", 0),
        max_poll_attempts=overrides.pop("max_poll_attempts", 3),
        **overrides,
    )
    return FordefiSigner(config)


def mock_vault(body: dict[str, Any], status_code: int = 200) -> None:
    respx.get(VAULT_URL).mock(return_value=httpx.Response(status_code, json=body))


def status_response(state: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"id": "tx-1", "state": state, **extra})


def mock_sign_flow(*poll_responses: httpx.Response) -> None:
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(side_effect=list(poll_responses))


def signature_b64(signature: Any) -> str:
    return base64.b64encode(bytes(signature)).decode("ascii")


def assert_valid_request_signature(request: httpx.Request) -> None:
    timestamp = request.headers["x-timestamp"]
    payload = f"/api/v1/transactions|{timestamp}|".encode() + request.content
    der_signature = base64.b64decode(request.headers["x-signature"])
    EC_PUBLIC_KEY.verify(der_signature, payload, ec.ECDSA(hashes.SHA256()))


class StaticRequestSigner(FordefiRequestSigner):
    async def sign_request(self, payload: bytes) -> str:
        return "static-signature"


def test_broadcasts_transactions_by_mode() -> None:
    keypair = Keypair()
    assert not make_signer(keypair).broadcasts_transactions
    assert make_signer(keypair, chain="solana_mainnet").broadcasts_transactions
    assert not make_signer(
        keypair, chain="solana_mainnet", push_mode="manual"
    ).broadcasts_transactions


def test_push_mode_type_and_default() -> None:
    mode: FordefiPushMode = "manual"
    keypair = Keypair()
    assert make_signer(keypair)._push_mode == "auto"
    assert make_signer(keypair, chain="solana_devnet", push_mode=mode)._push_mode == mode


@pytest.mark.parametrize("field", ["access_token", "vault_id", "public_key"])
def test_config_rejects_empty_required_field(field: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), **{field: ""})
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_both_key_mechanisms() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), request_signer=StaticRequestSigner())
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_missing_key_mechanism() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), private_key_pem=None)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_invalid_pem() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), private_key_pem="not-a-pem")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_config_rejects_non_p256_pem() -> None:
    other_key = ec.generate_private_key(ec.SECP384R1())
    pem = other_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), private_key_pem=pem)
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_config_rejects_invalid_public_key() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), public_key="not-a-pubkey")
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_config_rejects_http_url() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), api_base_url="http://insecure.example.com")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_unknown_chain() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), chain="solana_testnet")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_unknown_push_mode() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), chain="solana_devnet", push_mode="invalid")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_manual_push_mode_without_chain() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), push_mode="manual")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_fee_without_chain() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), fee={"type": "priority", "priority_level": "high"})
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_zero_max_poll_attempts() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), max_poll_attempts=0)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_negative_poll_interval() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_signer(Keypair(), poll_interval_ms=-1)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_factory_verifies_chain_specific_vault_address() -> None:
    keypair = Keypair()
    mock_vault({"id": VAULT_ID, "address": str(keypair.pubkey()), "type": "solana"})
    signer = await create_fordefi_signer(
        FordefiSignerConfig(
            access_token=ACCESS_TOKEN,
            vault_id=VAULT_ID,
            public_key=str(keypair.pubkey()),
            private_key_pem=EC_PRIVATE_PEM,
            api_base_url=API_BASE_URL,
        )
    )
    assert signer.pubkey == keypair.pubkey()


@respx.mock
async def test_factory_accepts_manual_push_mode() -> None:
    keypair = Keypair()
    mock_vault({"id": VAULT_ID, "address": str(keypair.pubkey()), "type": "solana"})
    signer = await create_fordefi_signer(
        FordefiSignerConfig(
            access_token=ACCESS_TOKEN,
            vault_id=VAULT_ID,
            public_key=str(keypair.pubkey()),
            private_key_pem=EC_PRIVATE_PEM,
            api_base_url=API_BASE_URL,
            chain="solana_devnet",
            push_mode="manual",
        )
    )
    assert not signer.broadcasts_transactions


@respx.mock
async def test_umbrella_factory_accepts_manual_config() -> None:
    keypair = Keypair()
    mock_vault({"id": VAULT_ID, "address": str(keypair.pubkey()), "type": "solana"})
    signer = await create_keychain_signer(
        "fordefi",
        FordefiSignerConfig(
            access_token=ACCESS_TOKEN,
            vault_id=VAULT_ID,
            public_key=str(keypair.pubkey()),
            private_key_pem=EC_PRIVATE_PEM,
            api_base_url=API_BASE_URL,
            chain="solana_mainnet",
            push_mode="manual",
        ),
    )
    assert isinstance(signer, FordefiSigner)
    assert not signer.broadcasts_transactions


@respx.mock
async def test_factory_derives_black_box_vault_address() -> None:
    keypair = Keypair()
    compressed = base64.b64encode(bytes(keypair.pubkey())).decode("ascii")
    mock_vault({"id": VAULT_ID, "public_key_compressed": compressed, "type": "black_box"})
    signer = make_signer(keypair)
    await signer.init()
    assert signer.pubkey == keypair.pubkey()


@respx.mock
async def test_init_rejects_vault_address_mismatch() -> None:
    mock_vault({"id": VAULT_ID, "address": str(Keypair().pubkey())})
    signer = make_signer(Keypair())
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_rejects_vault_without_public_key() -> None:
    mock_vault({"id": VAULT_ID})
    signer = make_signer(Keypair())
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_init_rejects_undecodable_compressed_key() -> None:
    mock_vault({"id": VAULT_ID, "public_key_compressed": "not-base64!"})
    signer = make_signer(Keypair())
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_init_rejects_wrong_length_compressed_key() -> None:
    compressed = base64.b64encode(b"\x01" * 31).decode("ascii")
    mock_vault({"id": VAULT_ID, "public_key_compressed": compressed})
    signer = make_signer(Keypair())
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


@respx.mock
async def test_init_propagates_vault_api_error() -> None:
    mock_vault({"detail": "unauthorized"}, status_code=401)
    signer = make_signer(Keypair())
    with pytest.raises(SignerError) as excinfo:
        await signer.init()
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_sign_message_black_box_success_with_stamped_request() -> None:
    keypair = Keypair()
    message = b"fordefi-message"
    signature = keypair.sign_message(message)
    signer = make_signer(keypair)
    mock_sign_flow(
        status_response("waiting_for_signing_trigger"),
        status_response("signed", signatures=[{"data": signature_b64(signature)}]),
    )

    result = await signer.sign_message(message)

    assert result == signature
    create_request = respx.calls[0].request
    assert create_request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert_valid_request_signature(create_request)
    assert "x-idempotence-id" not in create_request.headers
    body = json.loads(create_request.content)
    assert body == {
        "vault_id": VAULT_ID,
        "signer_type": "api_signer",
        "sign_mode": "auto",
        "type": "black_box_signature",
        "details": {
            "format": "hash_binary",
            "hash_binary": base64.b64encode(message).decode("ascii"),
        },
    }


@respx.mock
async def test_sign_message_uses_custom_request_signer() -> None:
    keypair = Keypair()
    message = b"custom-signer-message"
    signature = keypair.sign_message(message)
    signer = make_signer(keypair, private_key_pem=None, request_signer=StaticRequestSigner())
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    await signer.sign_message(message)

    assert respx.calls[0].request.headers["x-signature"] == "static-signature"


@respx.mock
async def test_sign_message_verification_failure() -> None:
    keypair = Keypair()
    message = b"fordefi-message"
    bogus = Keypair().sign_message(message)
    signer = make_signer(keypair)
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(bogus)}]))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_missing_signatures() -> None:
    signer = make_signer(Keypair())
    mock_sign_flow(status_response("signed"))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    signer = make_signer(Keypair())
    mock_sign_flow(status_response("signed", signatures=[{"data": "not-base64!"}]))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    signer = make_signer(Keypair())
    short = base64.b64encode(b"\x01" * 32).decode("ascii")
    mock_sign_flow(status_response("signed", signatures=[{"data": short}]))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
@pytest.mark.parametrize(
    "state",
    [
        "aborted",
        "cancelled",
        "completed_reverted",
        "dropped",
        "error_pushing_to_blockchain",
        "error_signing",
        "insufficient_funds",
        "mined_reverted",
    ],
)
async def test_sign_message_terminal_failure_state(state: str) -> None:
    signer = make_signer(Keypair())
    mock_sign_flow(status_response(state))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_polling_timeout() -> None:
    signer = make_signer(Keypair(), max_poll_attempts=3)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=status_response("waiting_for_signing_trigger")
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR
    assert len(respx.calls) == 4


@respx.mock
async def test_sign_transaction_native_polling_timeout_is_broadcast_unconfirmed() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", max_poll_attempts=3)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=status_response("waiting_for_signing_trigger")
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_native_submit_server_error_is_unconfirmed_without_a_transaction_id() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(502, json={"error": "bad gateway"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code == 502


@respx.mock
async def test_native_submit_accepted_without_an_id_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"state": "pending"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code is None


@respx.mock
async def test_native_submit_rejected_by_fordefi_stays_a_plain_failure() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_black_box_submit_server_error_is_not_reported_as_unconfirmed() -> None:
    """Black-box mode only signs, so a failed submit has no on-chain outcome to be
    unconfirmed about."""
    keypair = Keypair()
    signer = make_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(502, json={"error": "bad gateway"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_cancellation_during_native_submit_warns_without_a_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No id exists yet, so the warning is all the caller gets."""
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    submitting = asyncio.Event()
    observed: list[str] = []

    async def hang(_request: httpx.Request) -> httpx.Response:
        submitting.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(side_effect=hang)

    async def run() -> None:
        try:
            await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
        except asyncio.CancelledError as error:
            observed.append(str(error))
            raise

    task = asyncio.create_task(run())
    await submitting.wait()
    task.cancel()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert observed and "may have accepted the transaction" in observed[0]
    assert "check before retrying" in caplog.text


@respx.mock
async def test_sign_transaction_native_cancellation_carries_the_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The re-raised CancelledError must carry the provider transaction id, and
    the id must also be logged: awaiting the cancelled task yields a fresh
    CancelledError from the task machinery, without the message."""
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    polling = asyncio.Event()
    observed: list[str] = []

    async def hang(_request: httpx.Request) -> httpx.Response:
        polling.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(side_effect=hang)

    async def run() -> None:
        try:
            await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
        except asyncio.CancelledError as error:
            observed.append(str(error))
            raise

    task = asyncio.create_task(run())
    await polling.wait()
    task.cancel()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert observed and "tx-1" in observed[0]
    assert "tx-1" in caplog.text


@respx.mock
async def test_sign_transaction_black_box_success() -> None:
    keypair = Keypair()
    signer = make_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert result.encoded_transaction
    assert result.transaction is None
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_sign_message_native_mode_uses_solana_message() -> None:
    keypair = Keypair()
    message = b"native-message"
    signature = keypair.sign_message(message)
    signer = make_signer(keypair, chain="solana_devnet")
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    result = await signer.sign_message(message)

    assert result == signature
    body = json.loads(respx.calls[0].request.content)
    assert body["type"] == "solana_message"
    assert body["details"] == {
        "type": "personal_message_type",
        "chain": "solana_devnet",
        "raw_data": base64.b64encode(message).decode("ascii"),
    }


def make_signed_wire_transaction(keypair: Keypair) -> tuple[str, Any]:
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    transaction.signatures = [signature]
    return base64.b64encode(bytes(transaction)).decode("ascii"), signature


def create_transaction_version(version: str, payer: Pubkey) -> VersionedTransaction:
    if version == "legacy":
        return create_test_transaction(payer)
    if version == "v0":
        return create_test_v0_transaction(payer)
    if version == "v1":
        return create_test_v1_transaction(payer)
    raise AssertionError(f"unsupported test transaction version: {version}")


def signed_wire(keypair: Keypair, transaction: VersionedTransaction) -> tuple[str, Signature]:
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    signatures = list(transaction.signatures)
    signatures[0] = signature
    transaction.signatures = signatures
    return base64.b64encode(bytes(transaction)).decode("ascii"), signature


@respx.mock
async def test_sign_transaction_native_success() -> None:
    keypair = Keypair()
    signer = make_signer(
        keypair, chain="solana_mainnet", fee={"type": "priority", "priority_level": "high"}
    )
    raw_transaction, signature = make_signed_wire_transaction(keypair)
    mock_sign_flow(
        status_response("signed"),
        status_response("completed", raw_transaction=raw_transaction),
    )
    transaction = create_test_transaction(keypair.pubkey())

    result = await signer.sign_transaction(transaction)

    assert result.signature == signature
    assert result.encoded_transaction == ""
    assert result.is_complete
    assert result.transaction is None
    assert all(sig == Signature.default() for sig in transaction.signatures), (
        "the caller's transaction must be left untouched by provider-chosen bytes"
    )
    body = json.loads(respx.calls[0].request.content)
    assert body["type"] == "solana_transaction"
    assert body["details"]["type"] == "solana_serialized_transaction_message"
    assert body["details"]["chain"] == "solana_mainnet"
    assert body["details"]["push_mode"] == "auto"
    assert body["details"]["fee"] == {"type": "priority", "priority_level": "high"}
    assert body["details"]["data"] == base64.b64encode(
        signed_message_bytes(transaction.message)
    ).decode("ascii")
    digest = bytearray(hashlib.sha256(signed_message_bytes(transaction.message)).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    assert respx.calls[0].request.headers["x-idempotence-id"] == str(uuid.UUID(bytes=bytes(digest)))


@respx.mock
async def test_sign_transaction_native_missing_raw_transaction() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    mock_sign_flow(status_response("completed"))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_sign_transaction_native_verifies_against_returned_message() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    transaction = create_test_transaction(keypair.pubkey())
    returned = create_test_transaction(keypair.pubkey())
    returned.signatures = [keypair.sign_message(signed_message_bytes(transaction.message))]
    raw_transaction = base64.b64encode(bytes(returned)).decode("ascii")
    mock_sign_flow(status_response("completed", raw_transaction=raw_transaction))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_sign_transaction_native_rejects_multi_signer_before_submitting() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet")
    transaction = create_two_signer_transaction(keypair.pubkey(), Keypair().pubkey())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
@pytest.mark.parametrize(
    ("version", "terminal_state"),
    [("legacy", "signed"), ("v0", "completed"), ("v1", "signed")],
)
async def test_sign_transaction_native_manual_returns_modified_transaction(
    version: str, terminal_state: str
) -> None:
    keypair = Keypair()
    fee = {"type": "priority", "priority_level": "high"}
    signer = make_signer(
        keypair,
        chain="solana_mainnet",
        fee=fee,
        push_mode="manual",
    )
    transaction = create_transaction_version(version, keypair.pubkey())
    original_wire = bytes(transaction)
    returned = create_transaction_version(version, keypair.pubkey())
    assert signed_message_bytes(returned.message) != signed_message_bytes(transaction.message)
    raw_transaction, signature = signed_wire(keypair, returned)
    mock_sign_flow(
        status_response("waiting_for_signing_trigger"),
        status_response(terminal_state, raw_transaction=raw_transaction),
    )

    result = await signer.sign_transaction(transaction)

    assert bytes(transaction) == original_wire
    assert result.transaction is not None
    assert bytes(result.transaction) == bytes(returned)
    assert base64.b64decode(result.encoded_transaction, validate=True) == bytes(returned)
    assert result.signature == signature
    assert result.is_complete
    assert signature.verify(keypair.pubkey(), signed_message_bytes(result.transaction.message))

    request = respx.calls[0].request
    body = json.loads(request.content)
    assert body["type"] == "solana_transaction"
    assert body["details"] == {
        "type": "solana_serialized_transaction_message",
        "chain": "solana_mainnet",
        "data": base64.b64encode(signed_message_bytes(transaction.message)).decode("ascii"),
        "push_mode": "manual",
        "fee": fee,
    }
    namespace = f"fordefi:solana:manual:solana_mainnet:{VAULT_ID}:".encode() + signed_message_bytes(
        transaction.message
    )
    digest = bytearray(hashlib.sha256(namespace).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    manual_id = str(uuid.UUID(bytes=bytes(digest)))
    assert request.headers["x-idempotence-id"] == manual_id
    assert manual_id != idempotency_key_from_message(signed_message_bytes(transaction.message))


@respx.mock
async def test_sign_message_manual_mode_still_uses_solana_message() -> None:
    keypair = Keypair()
    message = b"manual-native-message"
    signature = keypair.sign_message(message)
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    assert await signer.sign_message(message) == signature
    body = json.loads(respx.calls[0].request.content)
    assert body["type"] == "solana_message"
    assert "push_mode" not in body["details"]


@respx.mock
async def test_sign_transaction_native_manual_returns_partial_multisigner_result() -> None:
    keypair = Keypair()
    cosigner = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_two_signer_transaction(keypair.pubkey(), cosigner.pubkey())
    returned = VersionedTransaction.from_bytes(bytes(transaction))
    vault_signature = keypair.sign_message(signed_message_bytes(returned.message))
    returned.signatures = [vault_signature, Signature.default()]
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    result = await signer.sign_transaction(transaction)

    assert not result.is_complete
    assert result.transaction is not None
    assert list(result.transaction.signatures) == [vault_signature, Signature.default()]
    assert all(signature == Signature.default() for signature in transaction.signatures)

    downstream = cosigner.sign_message(signed_message_bytes(result.transaction.message))
    result.transaction.signatures = [vault_signature, downstream]
    assert all(signature != Signature.default() for signature in result.transaction.signatures)


@respx.mock
async def test_sign_transaction_native_manual_rejects_presigned_input_before_submit() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_test_transaction(keypair.pubkey())
    transaction.signatures = [keypair.sign_message(signed_message_bytes(transaction.message))]

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
async def test_sign_transaction_native_manual_rejects_non_vault_fee_payer_before_submit() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_test_transaction(Keypair().pubkey())

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
async def test_sign_transaction_native_manual_rejects_missing_raw_transaction() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    mock_sign_flow(status_response("signed"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
@pytest.mark.parametrize(
    ("raw_transaction", "error_code"),
    [
        ("not-base64!", SignerErrorCode.SERIALIZATION_ERROR),
        (base64.b64encode(b"not a transaction").decode(), SignerErrorCode.SERIALIZATION_ERROR),
        (base64.b64encode(b"x" * 1233).decode(), SignerErrorCode.SIGNING_FAILED),
    ],
)
async def test_sign_transaction_native_manual_rejects_invalid_wire_transaction(
    raw_transaction: str, error_code: SignerErrorCode
) -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    mock_sign_flow(status_response("signed", raw_transaction=raw_transaction))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == error_code


@respx.mock
async def test_sign_transaction_native_manual_rejects_changed_signer_set() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_test_transaction(keypair.pubkey())
    returned = create_test_transaction(Keypair().pubkey())
    returned.signatures = [Signature.default()]
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_native_manual_rejects_invalid_signature_slot_count() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_test_transaction(keypair.pubkey())
    returned = VersionedTransaction.from_bytes(bytes(transaction))
    returned.signatures = []
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_native_manual_rejects_missing_vault_signature() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    returned = create_test_transaction(keypair.pubkey())
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_native_manual_rejects_invalid_vault_signature() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    returned = create_test_transaction(keypair.pubkey())
    returned.signatures = [Keypair().sign_message(signed_message_bytes(returned.message))]
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_native_manual_rejects_downstream_signature() -> None:
    keypair = Keypair()
    cosigner = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    transaction = create_two_signer_transaction(keypair.pubkey(), cosigner.pubkey())
    returned = VersionedTransaction.from_bytes(bytes(transaction))
    message = signed_message_bytes(returned.message)
    returned.signatures = [keypair.sign_message(message), cosigner.sign_message(message)]
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_transaction_native_manual_failure_is_not_broadcast_unconfirmed() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    mock_sign_flow(status_response("error_signing"))

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_sign_transaction_native_manual_polling_timeout_is_plain_api_error() -> None:
    keypair = Keypair()
    signer = make_signer(
        keypair,
        chain="solana_devnet",
        push_mode="manual",
        max_poll_attempts=2,
    )
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=status_response("waiting_for_signing_trigger")
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_sign_transaction_native_manual_submit_error_is_plain_api_error() -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(502, json={"error": "bad gateway"})
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_sign_transaction_native_manual_submit_cancellation_has_no_broadcast_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    submitting = asyncio.Event()

    async def hang(_request: httpx.Request) -> httpx.Response:
        submitting.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(side_effect=hang)
    task = asyncio.create_task(signer.sign_transaction(create_test_transaction(keypair.pubkey())))
    await submitting.wait()
    task.cancel()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert "Fordefi may have" not in caplog.text


@respx.mock
async def test_sign_transaction_native_manual_poll_cancellation_has_no_broadcast_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    keypair = Keypair()
    signer = make_signer(keypair, chain="solana_devnet", push_mode="manual")
    polling = asyncio.Event()

    async def hang(_request: httpx.Request) -> httpx.Response:
        polling.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(side_effect=hang)
    task = asyncio.create_task(signer.sign_transaction(create_test_transaction(keypair.pubkey())))
    await polling.wait()
    task.cancel()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert "Fordefi may have" not in caplog.text


@respx.mock
async def test_is_available_success() -> None:
    mock_vault({"id": VAULT_ID})
    assert await make_signer(Keypair()).is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    mock_vault({"detail": "forbidden"}, status_code=403)
    assert not await make_signer(Keypair()).is_available()


@respx.mock
async def test_is_available_false_on_failing_request_signer() -> None:
    class FailingRequestSigner(FordefiRequestSigner):
        async def sign_request(self, payload: bytes) -> str:
            raise RuntimeError("kms unavailable")

    mock_vault({"id": VAULT_ID})
    signer = make_signer(Keypair(), private_key_pem=None, request_signer=FailingRequestSigner())
    assert not await signer.is_available()


async def test_pem_request_signer_produces_verifiable_der_signature() -> None:
    payload = b"/api/v1/transactions|1700000000000|{}"
    value = await PemRequestSigner(EC_PRIVATE_PEM).sign_request(payload)
    EC_PUBLIC_KEY.verify(base64.b64decode(value), payload, ec.ECDSA(hashes.SHA256()))


def test_reprs_never_contain_secrets() -> None:
    keypair = Keypair()
    config = FordefiSignerConfig(
        access_token=ACCESS_TOKEN,
        vault_id=VAULT_ID,
        public_key=str(keypair.pubkey()),
        private_key_pem=EC_PRIVATE_PEM,
        api_base_url=API_BASE_URL,
    )
    signer = make_signer(keypair)
    for text in (repr(config), repr(signer)):
        assert ACCESS_TOKEN not in text
        assert "PRIVATE KEY" not in text
