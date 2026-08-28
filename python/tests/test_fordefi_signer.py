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
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message, MessageV0, MessageV1
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import (
    ModifyingSigner,
    PendingTransactionId,
    SendingSigner,
    TransactionSigner,
    signed_message_bytes,
)
from solana_keychain.core.transaction_util import idempotency_key_from_message
from solana_keychain.fordefi import (
    FordefiBlackBoxSigner,
    FordefiNativeAutoSigner,
    FordefiNativeManualSigner,
    FordefiRequestSigner,
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


def make_config(keypair: Keypair, **overrides: Any) -> FordefiSignerConfig:
    return FordefiSignerConfig(
        access_token=overrides.pop("access_token", ACCESS_TOKEN),
        vault_id=overrides.pop("vault_id", VAULT_ID),
        public_key=overrides.pop("public_key", str(keypair.pubkey())),
        private_key_pem=overrides.pop("private_key_pem", EC_PRIVATE_PEM),
        api_base_url=overrides.pop("api_base_url", API_BASE_URL),
        poll_interval_ms=overrides.pop("poll_interval_ms", 0),
        max_poll_attempts=overrides.pop("max_poll_attempts", 3),
        **overrides,
    )


def make_black_box_signer(keypair: Keypair, **overrides: Any) -> FordefiBlackBoxSigner:
    return FordefiBlackBoxSigner(make_config(keypair, **overrides))


def make_native_signer(keypair: Keypair, **overrides: Any) -> FordefiNativeAutoSigner:
    overrides.setdefault("chain", "solana_devnet")
    return FordefiNativeAutoSigner(make_config(keypair, **overrides))


def make_manual_signer(keypair: Keypair, **overrides: Any) -> FordefiNativeManualSigner:
    overrides.setdefault("chain", "solana_devnet")
    overrides.setdefault("push_mode", "manual")
    return FordefiNativeManualSigner(make_config(keypair, **overrides))


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


def test_each_mode_exposes_exactly_one_transaction_capability() -> None:
    """The mode is the type, so a caller cannot reach an entry point the vault
    shape does not support."""
    keypair = Keypair()
    black_box = make_black_box_signer(keypair)
    native = make_native_signer(keypair, chain="solana_mainnet")
    manual = make_manual_signer(keypair, chain="solana_mainnet")

    assert isinstance(black_box, TransactionSigner)
    assert not isinstance(black_box, SendingSigner | ModifyingSigner)
    assert isinstance(native, SendingSigner)
    assert not isinstance(native, TransactionSigner | ModifyingSigner)
    assert isinstance(manual, ModifyingSigner)
    assert not isinstance(manual, TransactionSigner | SendingSigner)


def test_black_box_signer_rejects_a_native_config() -> None:
    with pytest.raises(SignerError) as excinfo:
        FordefiBlackBoxSigner(make_config(Keypair(), chain="solana_mainnet"))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_black_box_signer_rejects_a_push_mode() -> None:
    """``push_mode`` is meaningless without a chain, so it must not be ignored."""
    with pytest.raises(SignerError) as excinfo:
        FordefiBlackBoxSigner(make_config(Keypair(), push_mode="auto"))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_native_signer_rejects_a_black_box_config() -> None:
    with pytest.raises(SignerError) as excinfo:
        FordefiNativeAutoSigner(make_config(Keypair()))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@pytest.mark.parametrize(
    ("signer_type", "overrides"),
    [
        (FordefiNativeAutoSigner, {"chain": "solana_devnet", "push_mode": "manual"}),
        (FordefiNativeManualSigner, {"chain": "solana_devnet"}),
        (FordefiNativeManualSigner, {"chain": "solana_devnet", "push_mode": "auto"}),
        (FordefiNativeManualSigner, {"push_mode": "manual"}),
    ],
)
def test_native_signer_rejects_the_other_modes_config(
    signer_type: type[FordefiNativeAutoSigner] | type[FordefiNativeManualSigner],
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(SignerError) as excinfo:
        signer_type(make_config(Keypair(), **overrides))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


async def test_factory_picks_the_signer_type_from_chain_and_push_mode() -> None:
    keypair = Keypair()
    black_box = await create_fordefi_signer(make_config(keypair))
    native = await create_fordefi_signer(make_config(keypair, chain="solana_devnet"))
    auto = await create_fordefi_signer(
        make_config(keypair, chain="solana_devnet", push_mode="auto")
    )
    manual = await create_fordefi_signer(
        make_config(keypair, chain="solana_devnet", push_mode="manual")
    )
    assert isinstance(black_box, FordefiBlackBoxSigner)
    assert isinstance(native, FordefiNativeAutoSigner)
    assert isinstance(auto, FordefiNativeAutoSigner)
    assert isinstance(manual, FordefiNativeManualSigner)


@pytest.mark.parametrize("field", ["access_token", "vault_id", "public_key"])
def test_config_rejects_empty_required_field(field: str) -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), **{field: ""})
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_both_key_mechanisms() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), request_signer=StaticRequestSigner())
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_missing_key_mechanism() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), private_key_pem=None)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_invalid_pem() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), private_key_pem="not-a-pem")
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_config_rejects_non_p256_pem() -> None:
    other_key = ec.generate_private_key(ec.SECP384R1())
    pem = other_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), private_key_pem=pem)
    assert excinfo.value.code == SignerErrorCode.INVALID_PRIVATE_KEY


def test_config_rejects_invalid_public_key() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), public_key="not-a-pubkey")
    assert excinfo.value.code == SignerErrorCode.INVALID_PUBLIC_KEY


def test_config_rejects_http_url() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), api_base_url="http://insecure.example.com")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_unknown_chain() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_native_signer(Keypair(), chain="solana_testnet")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_black_box_config_rejects_a_fee() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), fee={"type": "priority", "priority_level": "high"})
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_zero_max_poll_attempts() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), max_poll_attempts=0)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_config_rejects_negative_poll_interval() -> None:
    with pytest.raises(SignerError) as excinfo:
        make_black_box_signer(Keypair(), poll_interval_ms=-1)
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_factory_uses_configured_public_key_without_remote_calls() -> None:
    keypair = Keypair()
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
    assert not respx.calls


@respx.mock
async def test_sign_message_black_box_success_with_stamped_request() -> None:
    keypair = Keypair()
    message = b"fordefi-message"
    signature = keypair.sign_message(message)
    signer = make_black_box_signer(keypair)
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
    signer = make_black_box_signer(
        keypair, private_key_pem=None, request_signer=StaticRequestSigner()
    )
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    await signer.sign_message(message)

    assert respx.calls[0].request.headers["x-signature"] == "static-signature"


@respx.mock
async def test_sign_message_verification_failure() -> None:
    keypair = Keypair()
    message = b"fordefi-message"
    bogus = Keypair().sign_message(message)
    signer = make_black_box_signer(keypair)
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(bogus)}]))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(message)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_missing_signatures() -> None:
    signer = make_black_box_signer(Keypair())
    mock_sign_flow(status_response("signed"))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_undecodable_signature() -> None:
    signer = make_black_box_signer(Keypair())
    mock_sign_flow(status_response("signed", signatures=[{"data": "not-base64!"}]))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SERIALIZATION_ERROR


@respx.mock
async def test_sign_message_wrong_length_signature() -> None:
    signer = make_black_box_signer(Keypair())
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
    signer = make_black_box_signer(Keypair())
    mock_sign_flow(status_response(state))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_message(b"hello")
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_sign_message_polling_timeout() -> None:
    signer = make_black_box_signer(Keypair(), max_poll_attempts=3)
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
    signer = make_native_signer(keypair, chain="solana_devnet", max_poll_attempts=3)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=status_response("waiting_for_signing_trigger")
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_native_submit_server_error_is_unconfirmed_without_a_transaction_id() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(502, json={"error": "bad gateway"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code == 502


@respx.mock
async def test_native_submit_accepted_with_an_empty_id_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": ""}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_native_submit_accepted_without_an_id_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"state": "pending"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code is None


@respx.mock
async def test_native_submit_timed_out_while_processing_is_unconfirmed() -> None:
    """A 408 is a timeout reached while the create was processed, not a rejection."""
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(408, json={"detail": "Reached time out while processing"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code == 408


@respx.mock
async def test_native_submit_rejected_by_fordefi_stays_a_plain_failure() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_black_box_submit_server_error_is_not_reported_as_unconfirmed() -> None:
    """Black-box mode only signs, so a failed submit has no on-chain outcome to be
    unconfirmed about."""
    keypair = Keypair()
    signer = make_black_box_signer(keypair)
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
    signer = make_native_signer(keypair, chain="solana_devnet")
    submitting = asyncio.Event()
    observed: list[str] = []

    async def hang(_request: httpx.Request) -> httpx.Response:
        submitting.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(side_effect=hang)

    async def run() -> None:
        try:
            await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
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
    signer = make_native_signer(keypair, chain="solana_devnet")
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
            await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
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
async def test_native_cancellation_leaves_the_transaction_id_in_the_pending_slot() -> None:
    """Awaiting a cancelled task discards the raised message, so the registered
    slot is the only structured carrier for the id the caller must reconcile."""
    keypair = Keypair()
    pending = PendingTransactionId()
    signer = make_native_signer(keypair, chain="solana_devnet", pending_transaction_id=pending)
    polling = asyncio.Event()

    async def hang(_request: httpx.Request) -> httpx.Response:
        polling.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"id": "tx-1"}))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(side_effect=hang)

    task = asyncio.create_task(
        signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    )
    await polling.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pending.get() == "tx-1"


@respx.mock
async def test_sign_transaction_black_box_success() -> None:
    keypair = Keypair()
    signer = make_black_box_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert result.signature == signature
    assert result.encoded_transaction
    assert list(transaction.signatures) == [signature]


@respx.mock
async def test_sign_message_native_mode_uses_solana_message() -> None:
    keypair = Keypair()
    message = b"native-message"
    signature = keypair.sign_message(message)
    signer = make_native_signer(keypair, chain="solana_devnet")
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


@respx.mock
async def test_sign_transaction_native_success() -> None:
    keypair = Keypair()
    signer = make_native_signer(
        keypair, chain="solana_mainnet", fee={"type": "priority", "priority_level": "high"}
    )
    raw_transaction, signature = make_signed_wire_transaction(keypair)
    mock_sign_flow(
        status_response("signed"),
        status_response("completed", raw_transaction=raw_transaction),
    )
    transaction = create_test_transaction(keypair.pubkey())

    result = await signer.sign_and_send_transaction(transaction)

    assert result == signature
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
    signer = make_native_signer(keypair, chain="solana_devnet")
    mock_sign_flow(status_response("completed"))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_sign_transaction_native_verifies_against_returned_message() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    transaction = create_test_transaction(keypair.pubkey())
    returned = create_test_transaction(keypair.pubkey())
    returned.signatures = [keypair.sign_message(signed_message_bytes(transaction.message))]
    raw_transaction = base64.b64encode(bytes(returned)).decode("ascii")
    mock_sign_flow(status_response("completed", raw_transaction=raw_transaction))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_sign_transaction_native_rejects_multi_signer_before_submitting() -> None:
    keypair = Keypair()
    signer = make_native_signer(keypair, chain="solana_devnet")
    transaction = create_two_signer_transaction(keypair.pubkey(), Keypair().pubkey())
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


def replace_blockhash(transaction: VersionedTransaction, blockhash: Hash) -> VersionedTransaction:
    """Stand in for the rewrite Fordefi performs before signing."""
    message = transaction.message
    replaced: Message | MessageV0 | MessageV1
    if isinstance(message, Message):
        header = message.header
        replaced = Message.new_with_compiled_instructions(
            header.num_required_signatures,
            header.num_readonly_signed_accounts,
            header.num_readonly_unsigned_accounts,
            message.account_keys,
            blockhash,
            message.instructions,
        )
    elif isinstance(message, MessageV0):
        replaced = MessageV0(
            message.header,
            message.account_keys,
            blockhash,
            message.instructions,
            message.address_table_lookups,
        )
    else:
        replaced = MessageV1(
            message.header,
            message.config,
            blockhash,
            message.account_keys,
            message.instructions,
        )
    return VersionedTransaction.populate(
        replaced, [Signature.default()] * replaced.header.num_required_signatures
    )


def vault_signed_wire(
    keypair: Keypair, transaction: VersionedTransaction, position: int = 0
) -> tuple[str, Signature]:
    signature = keypair.sign_message(signed_message_bytes(transaction.message))
    signatures = list(transaction.signatures)
    signatures[position] = signature
    transaction.signatures = signatures
    return base64.b64encode(bytes(transaction)).decode("ascii"), signature


@respx.mock
@pytest.mark.parametrize("version", ["legacy", "v0", "v1"])
async def test_manual_signing_returns_the_transaction_fordefi_signed(version: str) -> None:
    """Fordefi signed bytes it chose, so only its own transaction can be broadcast."""
    keypair = Keypair()
    fee = {"type": "priority", "priority_level": "high"}
    signer = make_manual_signer(keypair, chain="solana_mainnet", fee=fee)
    builders = {
        "legacy": create_test_transaction,
        "v0": create_test_v0_transaction,
        "v1": create_test_v1_transaction,
    }
    transaction = builders[version](keypair.pubkey())
    original_wire = bytes(transaction)
    returned = replace_blockhash(transaction, Hash.new_unique())
    raw_transaction, signature = vault_signed_wire(keypair, returned)
    mock_sign_flow(
        status_response("waiting_for_signing_trigger"),
        status_response("signed", raw_transaction=raw_transaction),
    )

    result = await signer.modify_and_sign_transaction(transaction)

    assert bytes(transaction) == original_wire, "the caller's transaction must stay untouched"
    assert bytes(result.transaction) == bytes(returned)
    assert base64.b64decode(result.encoded_transaction, validate=True) == bytes(returned)
    assert result.signature == signature
    assert result.is_complete
    assert signature.verify(keypair.pubkey(), signed_message_bytes(result.transaction.message))

    assert json.loads(respx.calls[0].request.content)["details"] == {
        "type": "solana_serialized_transaction_message",
        "chain": "solana_mainnet",
        "data": base64.b64encode(signed_message_bytes(transaction.message)).decode("ascii"),
        "push_mode": "manual",
        "fee": fee,
    }


@respx.mock
async def test_manual_idempotence_id_cannot_collide_with_an_auto_create() -> None:
    """The same bytes under auto were broadcast, so the manual create must not
    dedupe onto them."""
    keypair = Keypair()
    signer = make_manual_signer(keypair, chain="solana_mainnet")
    transaction = create_test_transaction(keypair.pubkey())
    message_data = signed_message_bytes(transaction.message)
    raw_transaction, _ = vault_signed_wire(
        keypair, replace_blockhash(transaction, Hash.new_unique())
    )
    mock_sign_flow(status_response("signed", raw_transaction=raw_transaction))

    await signer.modify_and_sign_transaction(transaction)

    namespaced = f"fordefi:solana:manual:solana_mainnet:{VAULT_ID}:".encode() + message_data
    observed = respx.calls[0].request.headers["x-idempotence-id"]
    assert observed == idempotency_key_from_message(namespaced)
    assert observed != idempotency_key_from_message(message_data)


@respx.mock
async def test_manual_signing_returns_a_partial_multi_signer_transaction() -> None:
    """Downstream signers have to sign the bytes Fordefi produced, not the
    caller's, so the rewrite is what they must continue from."""
    keypair = Keypair()
    cosigner = Keypair()
    signer = make_manual_signer(keypair)
    transaction = create_two_signer_transaction(keypair.pubkey(), cosigner.pubkey())
    returned = replace_blockhash(transaction, Hash.new_unique())
    raw_transaction, vault_signature = vault_signed_wire(keypair, returned)
    mock_sign_flow(status_response("signed", raw_transaction=raw_transaction))

    result = await signer.modify_and_sign_transaction(transaction)

    assert not result.is_complete
    assert list(result.transaction.signatures) == [vault_signature, Signature.default()]
    assert all(signature == Signature.default() for signature in transaction.signatures)


@respx.mock
async def test_manual_signing_finds_the_vault_signature_by_account_position() -> None:
    """The vault pays the fee, but its signature slot is located by account
    position rather than assumed to be slot zero."""
    keypair = Keypair()
    cosigner = Keypair()
    signer = make_manual_signer(keypair)
    transaction = create_two_signer_transaction(keypair.pubkey(), cosigner.pubkey())
    returned = create_two_signer_transaction(cosigner.pubkey(), keypair.pubkey())
    raw_transaction, vault_signature = vault_signed_wire(keypair, returned, position=1)
    mock_sign_flow(status_response("signed", raw_transaction=raw_transaction))

    result = await signer.modify_and_sign_transaction(transaction)

    assert result.signature == vault_signature
    assert list(result.transaction.signatures)[1] == vault_signature


@respx.mock
async def test_manual_signing_rejects_a_signature_over_other_bytes() -> None:
    """An unverifiable signature must never reach the caller as a signed transaction."""
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    original_wire = bytes(transaction)
    returned = replace_blockhash(transaction, Hash.new_unique())
    returned.signatures = [Keypair().sign_message(signed_message_bytes(returned.message))]
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert bytes(transaction) == original_wire


@respx.mock
async def test_manual_signing_rejects_an_empty_vault_signature_slot() -> None:
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    returned = replace_blockhash(create_test_transaction(keypair.pubkey()), Hash.new_unique())
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_manual_signing_rejects_a_transaction_the_vault_cannot_sign() -> None:
    """A returned transaction with no slot for the vault carries no signature of ours."""
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    returned = create_test_transaction(Keypair().pubkey())
    mock_sign_flow(
        status_response("signed", raw_transaction=base64.b64encode(bytes(returned)).decode("ascii"))
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED


@respx.mock
async def test_manual_signing_rejects_a_non_vault_fee_payer_before_submitting() -> None:
    """Fordefi only rewrites transactions its own vault pays for."""
    keypair = Keypair()
    signer = make_manual_signer(keypair)

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(create_test_transaction(Keypair().pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
async def test_manual_signing_rejects_a_presigned_transaction_before_submitting() -> None:
    """Fordefi rewrites the message, which would silently void an existing signature."""
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    transaction.signatures = [keypair.sign_message(signed_message_bytes(transaction.message))]

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert not respx.calls


@respx.mock
@pytest.mark.parametrize(
    ("raw_transaction", "error_code"),
    [
        (None, SignerErrorCode.SIGNING_FAILED),
        ("not-base64!", SignerErrorCode.SERIALIZATION_ERROR),
        (base64.b64encode(b"not a transaction").decode(), SignerErrorCode.SERIALIZATION_ERROR),
    ],
)
async def test_manual_signing_rejects_an_unusable_wire_transaction(
    raw_transaction: str | None, error_code: SignerErrorCode
) -> None:
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    extra = {} if raw_transaction is None else {"raw_transaction": raw_transaction}
    mock_sign_flow(status_response("signed", **extra))

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == error_code


@respx.mock
async def test_manual_signing_failure_is_never_broadcast_unconfirmed() -> None:
    """Nothing is broadcast in manual mode, so a failure leaves no on-chain doubt."""
    keypair = Keypair()
    signer = make_manual_signer(keypair)
    mock_sign_flow(status_response("error_signing"))

    with pytest.raises(SignerError) as excinfo:
        await signer.modify_and_sign_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.SIGNING_FAILED
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_manual_mode_signs_messages_through_solana_message() -> None:
    keypair = Keypair()
    message = b"manual-native-message"
    signature = keypair.sign_message(message)
    signer = make_manual_signer(keypair)
    mock_sign_flow(status_response("signed", signatures=[{"data": signature_b64(signature)}]))

    assert await signer.sign_message(message) == signature
    body = json.loads(respx.calls[0].request.content)
    assert body["type"] == "solana_message"
    assert "push_mode" not in body["details"]


@respx.mock
async def test_is_available_success() -> None:
    mock_vault({"id": VAULT_ID})
    assert await make_black_box_signer(Keypair()).is_available()


@respx.mock
async def test_is_available_false_on_api_error() -> None:
    mock_vault({"detail": "forbidden"}, status_code=403)
    assert not await make_black_box_signer(Keypair()).is_available()


@respx.mock
async def test_is_available_false_on_failing_request_signer() -> None:
    class FailingRequestSigner(FordefiRequestSigner):
        async def sign_request(self, payload: bytes) -> str:
            raise RuntimeError("kms unavailable")

    mock_vault({"id": VAULT_ID})
    signer = make_black_box_signer(
        Keypair(), private_key_pem=None, request_signer=FailingRequestSigner()
    )
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
    signers = (
        make_black_box_signer(keypair),
        make_native_signer(keypair),
        make_manual_signer(keypair),
    )
    for text in (repr(config), *(repr(signer) for signer in signers)):
        assert ACCESS_TOKEN not in text
        assert "PRIVATE KEY" not in text
