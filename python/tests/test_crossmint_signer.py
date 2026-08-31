import asyncio
import hashlib
import json
import logging
import uuid
from typing import Any

import base58
import httpx
import pytest
import respx
from solders.keypair import Keypair
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain import SignerError, SignerErrorCode
from solana_keychain.core import (
    PendingTransactionId,
    SendingSigner,
    TransactionSigner,
    signed_message_bytes,
)
from solana_keychain.crossmint import (
    CrossmintSigner,
    CrossmintSignerConfig,
    create_crossmint_signer,
)
from solana_keychain.crossmint.derive import derive_signing_key, parse_api_key
from tests.util import (
    create_test_transaction,
    create_test_v1_transaction,
    create_two_signer_transaction,
)

API_BASE_URL = "https://crossmint.example.com/api"
API_KEY = "sk_staging_" + base58.b58encode(b"project-123:nacl-sig").decode()
SIGNER_SECRET = "xmsk1_" + "ab" * 32
WALLET_LOCATOR = "email:user@test.com:solana"
ENCODED_LOCATOR = "email%3Auser%40test.com%3Asolana"
WALLET_URL = f"{API_BASE_URL}/2025-06-09/wallets/{ENCODED_LOCATOR}"
TRANSACTIONS_URL = f"{WALLET_URL}/transactions"


def assert_caller_transaction_untouched(transaction: VersionedTransaction) -> None:
    assert all(signature == Signature.default() for signature in transaction.signatures), (
        "Crossmint broadcasts server-side, so the caller's transaction must stay unsigned"
    )


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
    signed.signatures = [keypair.sign_message(signed_message_bytes(transaction.message))]
    return base58.b58encode(bytes(signed)).decode()


def tx_response(status: str, tx_id: str = "tx-1", **extra: Any) -> dict[str, Any]:
    return {"id": tx_id, "status": status, **extra}


def test_parse_api_key() -> None:
    assert parse_api_key(API_KEY) == ("project-123", "staging")
    with pytest.raises(SignerError) as excinfo:
        parse_api_key("sk_missing-data")
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


def test_exposes_only_the_sending_capability() -> None:
    """Crossmint has no sign-only API: an approved transaction is always executed
    server-side, so there is no sign_transaction for a caller to reach for."""
    signer = make_signer()
    assert isinstance(signer, SendingSigner)
    assert not isinstance(signer, TransactionSigner)
    assert not hasattr(signer, "sign_transaction")


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


def test_the_idempotency_key_input_is_namespaced_by_the_signer_locator() -> None:
    """Pins the exact bytes hashed into the idempotency key. Every language must
    derive the same key from the same locator and message."""
    signer = make_signer()
    assert signer._namespaced_key_input(b"MSG") == b"crossmint:solana:0::MSG"

    signer = make_signer(signer="server:abc")
    assert signer._namespaced_key_input(b"MSG") == b"crossmint:solana:10:server:abc:MSG"


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


async def test_uninitialized_sign_and_send_transaction_raises_not_initialized() -> None:
    signer = make_signer()
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(Keypair().pubkey()))
    assert excinfo.value.code == SignerErrorCode.NOT_INITIALIZED


@respx.mock
async def test_sign_and_send_transaction_success_from_embedded_transaction() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    unsigned_bytes = bytes(transaction)
    expected_signature = keypair.sign_message(signed_message_bytes(transaction.message))

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

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
    create_body = json.loads(respx.calls[1].request.content)
    assert "signer" not in create_body["params"]
    assert base58.b58decode(create_body["params"]["transaction"]) == unsigned_bytes
    digest = bytearray(
        hashlib.sha256(
            b"crossmint:solana:0::" + signed_message_bytes(transaction.message)
        ).digest()[:16]
    )
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    assert respx.calls[1].request.headers["x-idempotency-key"] == str(
        uuid.UUID(bytes=bytes(digest))
    )


@respx.mock
async def test_sign_and_send_transaction_falls_back_to_tx_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    signature = keypair.sign_message(signed_message_bytes(transaction.message))

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(signature)})
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)
    assert signature == signature


@respx.mock
async def test_sign_and_send_transaction_accepts_provider_tx_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    other_signature = keypair.sign_message(b"different bytes")

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(other_signature)})
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)
    assert signature == other_signature


@respx.mock
async def test_sign_and_send_transaction_failed_status() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json=tx_response("failed", error={"reason": "boom"}))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_sign_and_send_transaction_polling_timeout() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, max_poll_attempts=2)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json=tx_response("pending")))
    respx.get(f"{TRANSACTIONS_URL}/tx-1").mock(
        return_value=httpx.Response(200, json=tx_response("pending"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_create_server_error_is_unconfirmed_without_a_transaction_id() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(503, json={"error": "service unavailable"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code == 503


@respx.mock
async def test_create_server_error_keeps_a_transaction_id_from_the_body() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(503, json={"id": "tx-accepted"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-accepted"
    assert excinfo.value.status_code == 503


@respx.mock
async def test_an_unconfirmed_create_carries_the_key_it_was_submitted_under() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    route = respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(503, json={"message": "unavailable"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    sent_key = route.calls[0].request.headers["x-idempotency-key"]
    assert excinfo.value.idempotency_key == sent_key


@respx.mock
async def test_create_accepted_without_an_id_is_unconfirmed() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json={"status": "pending"}))
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None
    assert excinfo.value.status_code is None


@respx.mock
async def test_create_accepted_with_a_blank_id_is_unconfirmed_without_one() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json={"id": "   ", "status": "pending"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id is None


@respx.mock
async def test_create_rejected_by_crossmint_stays_a_plain_failure() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(400, json={"error": "invalid transaction"})
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.REMOTE_API_ERROR


@respx.mock
async def test_cancellation_during_create_warns_without_a_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No id exists yet, so the warning is all the caller gets."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    creating = asyncio.Event()
    observed: list[str] = []

    async def hang(_request: httpx.Request) -> httpx.Response:
        creating.set()
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
    await creating.wait()
    task.cancel()
    with caplog.at_level(logging.WARNING, logger="solana_keychain"):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert observed and "may have created the transaction" in observed[0]
    assert "check before retrying" in caplog.text


@respx.mock
async def test_cancellation_after_create_carries_the_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The re-raised CancelledError must carry the provider transaction id, and the
    id must also be logged: awaiting the cancelled task yields a fresh
    CancelledError from the task machinery, without the message."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    polling = asyncio.Event()
    observed: list[str] = []

    async def hang(_request: httpx.Request) -> httpx.Response:
        polling.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json=tx_response("pending")))
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
async def test_cancellation_after_create_leaves_the_transaction_id_in_the_pending_slot() -> None:
    """Awaiting a cancelled task discards the raised message, so the registered
    slot is the only structured carrier for the id the caller must reconcile."""
    keypair = Keypair()
    pending = PendingTransactionId()
    signer = await initialized_signer(keypair, pending_transaction_id=pending)
    polling = asyncio.Event()

    async def hang(_request: httpx.Request) -> httpx.Response:
        polling.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    respx.post(TRANSACTIONS_URL).mock(return_value=httpx.Response(200, json=tx_response("pending")))
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
async def test_a_completed_send_leaves_no_id_in_the_pending_slot() -> None:
    """A stale id would send the caller reconciling a transaction they already
    have the signature for."""
    keypair = Keypair()
    pending = PendingTransactionId()
    signer = await initialized_signer(keypair, pending_transaction_id=pending)
    transaction = create_test_transaction(keypair.pubkey())

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

    await signer.sign_and_send_transaction(transaction)
    assert pending.get() is None


@respx.mock
async def test_awaiting_approval_without_signer_key_fails() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(200, json=tx_response("awaiting-approval"))
    )
    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_awaiting_approval_signs_only_our_pending_entry() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair, signer_secret=SIGNER_SECRET)
    transaction = create_test_transaction(keypair.pubkey())
    expected_signature = keypair.sign_message(signed_message_bytes(transaction.message))
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

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
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
        await signer.sign_and_send_transaction(create_test_transaction(keypair.pubkey()))
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


@respx.mock
async def test_rewritten_transaction_is_reported_as_a_broadcast_result() -> None:
    """Crossmint sponsors gas, so it is the fee payer and the message it signs
    differs from the caller's. Its signature must never be placed in the caller's
    transaction, which could not verify with it."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())

    rewritten = create_test_transaction(keypair.pubkey())
    assert signed_message_bytes(rewritten.message) != signed_message_bytes(transaction.message)
    expected_signature = keypair.sign_message(signed_message_bytes(rewritten.message))
    rewritten.signatures = [expected_signature]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
    assert all(sig == Signature.default() for sig in transaction.signatures)
    assert not expected_signature.verify(
        keypair.pubkey(), signed_message_bytes(transaction.message)
    )


@respx.mock
async def test_a_v1_returned_transaction_yields_its_signature() -> None:
    """The signer submits v1 transactions, so a v1 envelope coming back is not an
    unsupported version: rejecting it would discard a signature already in hand."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())

    rewritten = create_test_v1_transaction(keypair.pubkey())
    expected_signature = keypair.sign_message(signed_message_bytes(rewritten.message))
    rewritten.signatures = [expected_signature]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    assert await signer.sign_and_send_transaction(transaction) == expected_signature


@respx.mock
async def test_delegated_signer_signature_is_located_and_verified() -> None:
    """A smart wallet is signed by its delegated signer, not by the wallet address
    the API reports, so the delegated key must be a verification candidate."""
    wallet_keypair = Keypair()
    delegated = derive_signing_key(SIGNER_SECRET, API_KEY)
    assert delegated.pubkey() != wallet_keypair.pubkey()
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    rewritten = create_test_transaction(delegated.pubkey())
    expected_signature = delegated.sign_message(signed_message_bytes(rewritten.message))
    rewritten.signatures = [expected_signature]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
    # The wallet address is still the signer's public identity.
    assert signer.pubkey == wallet_keypair.pubkey()


@respx.mock
async def test_explicit_locator_signer_is_a_candidate_alongside_the_derived_key() -> None:
    """A wallet can be configured with both ``signer_secret`` and an explicit
    ``signer`` locator naming a different key, e.g. the wallet's admin signer.
    Either may be the key that actually signs, so both must be candidates."""
    wallet_keypair = Keypair()
    admin = Keypair()
    signer = await initialized_signer(
        wallet_keypair,
        signer_secret=SIGNER_SECRET,
        signer=f"server:{admin.pubkey()}",
    )

    transaction = create_test_transaction(wallet_keypair.pubkey())
    rewritten = create_test_transaction(admin.pubkey())
    expected_signature = admin.sign_message(signed_message_bytes(rewritten.message))
    rewritten.signatures = [expected_signature]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature


@respx.mock
async def test_wallet_address_in_an_unsigned_slot_does_not_shadow_the_delegated_signer() -> None:
    """The wallet address can occupy a required-signer slot it never signed while the
    delegated signer holds the real signature. Selection must not stop at the first
    candidate that merely appears in a slot."""
    wallet_keypair = Keypair()
    delegated = derive_signing_key(SIGNER_SECRET, API_KEY)
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    # Both keys are required signers and only the delegated signer actually
    # signed; the wallet address occupies a slot it never signed.
    rewritten = create_two_signer_transaction(delegated.pubkey(), wallet_keypair.pubkey())
    expected_signature = delegated.sign_message(signed_message_bytes(rewritten.message))
    rewritten.signatures = [expected_signature, Signature.default()]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature


@respx.mock
async def test_tx_id_signed_by_the_delegated_signer_is_accepted() -> None:
    """A txId proves the caller's bytes were signed, but any configured signer may
    have produced it: a smart wallet signs with its delegated signer, not the wallet
    address the API reports."""
    wallet_keypair = Keypair()
    delegated = derive_signing_key(SIGNER_SECRET, API_KEY)
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    expected_signature = delegated.sign_message(signed_message_bytes(transaction.message))

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(expected_signature)})
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature


@respx.mock
async def test_rewritten_transaction_approval_yields_the_fee_payer_transaction_id() -> None:
    """Under sponsorship the returned signature must be the fee payer's, not the
    wallet's approval, so RPC lookups resolve."""
    wallet_keypair = Keypair()
    delegated = derive_signing_key(SIGNER_SECRET, API_KEY)
    fee_payer = Keypair()
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    # As Crossmint returns it: its fee payer signed, this wallet's slot is empty.
    executed = create_two_signer_transaction(fee_payer.pubkey(), delegated.pubkey())
    fee_payer_signature = fee_payer.sign_message(signed_message_bytes(executed.message))
    executed.signatures = [
        fee_payer_signature,
        Signature.default(),
    ]
    approval_signature = delegated.sign_message(signed_message_bytes(executed.message))

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(executed)).decode()},
                approvals={
                    "pending": [],
                    "submitted": [
                        {
                            "signature": str(approval_signature),
                            "signer": {
                                "type": "server",
                                "address": str(delegated.pubkey()),
                                "locator": f"server:{delegated.pubkey()}",
                            },
                            "message": base58.b58encode(
                                signed_message_bytes(executed.message)
                            ).decode(),
                        }
                    ],
                },
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == fee_payer_signature
    assert signature != approval_signature
    assert all(sig == Signature.default() for sig in transaction.signatures)


@respx.mock
async def test_provider_transaction_is_trusted_without_approval_verification() -> None:
    wallet_keypair = Keypair()
    stranger = Keypair()
    fee_payer = Keypair()
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    executed = create_two_signer_transaction(fee_payer.pubkey(), stranger.pubkey())
    executed.signatures = [
        fee_payer.sign_message(signed_message_bytes(executed.message)),
        Signature.default(),
    ]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(executed)).decode()},
                approvals={
                    "pending": [],
                    "submitted": [
                        {
                            "signature": str(
                                stranger.sign_message(signed_message_bytes(executed.message))
                            ),
                            "signer": {"type": "server", "address": str(stranger.pubkey())},
                            "message": base58.b58encode(
                                signed_message_bytes(executed.message)
                            ).decode(),
                        }
                    ],
                },
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)
    assert signature == executed.signatures[0]


@respx.mock
async def test_provider_rewritten_transaction_is_trusted() -> None:
    wallet_keypair = Keypair()
    signer = await initialized_signer(wallet_keypair, signer_secret=SIGNER_SECRET)

    transaction = create_test_transaction(wallet_keypair.pubkey())
    stranger = Keypair()
    rewritten = create_test_transaction(stranger.pubkey())
    rewritten.signatures = [stranger.sign_message(signed_message_bytes(rewritten.message))]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(rewritten)).decode()},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)
    assert signature == rewritten.signatures[0]


@respx.mock
async def test_unrewritten_returned_transaction_is_not_placed_in_the_caller_transaction() -> None:
    """When Crossmint returns the submitted message unchanged, the signature does
    cover the caller's bytes, so it belongs in the caller's transaction."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    expected_signature = keypair.sign_message(signed_message_bytes(transaction.message))

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": signed_transaction_b58(keypair, transaction)},
            ),
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
    assert_caller_transaction_untouched(transaction)


@respx.mock
async def test_caller_exact_signature_is_returned_without_touching_the_transaction() -> None:
    """Even when Crossmint signs the submitted bytes unchanged, it has already
    executed them, so the caller's transaction is left alone."""
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())
    expected_signature = keypair.sign_message(signed_message_bytes(transaction.message))

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200, json=tx_response("success", onChain={"txId": str(expected_signature)})
        )
    )

    signature = await signer.sign_and_send_transaction(transaction)

    assert signature == expected_signature
    assert_caller_transaction_untouched(transaction)


@respx.mock
async def test_signature_not_covering_returned_transaction_is_rejected() -> None:
    keypair = Keypair()
    signer = await initialized_signer(keypair)
    transaction = create_test_transaction(keypair.pubkey())

    returned = create_test_transaction(keypair.pubkey())
    returned.signatures = [keypair.sign_message(b"unrelated bytes")]

    respx.post(TRANSACTIONS_URL).mock(
        return_value=httpx.Response(
            200,
            json=tx_response(
                "success",
                onChain={"transaction": base58.b58encode(bytes(returned)).decode()},
            ),
        )
    )

    with pytest.raises(SignerError) as excinfo:
        await signer.sign_and_send_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


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
        await signer.sign_and_send_transaction(transaction)
    assert excinfo.value.code == SignerErrorCode.BROADCAST_UNCONFIRMED
    assert excinfo.value.provider_transaction_id == "tx-1"


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
