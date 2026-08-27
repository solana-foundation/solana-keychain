"""Shared plumbing for the live integration suite.

Every test here talks to a real service. Tests are gated by the ``integration``
marker (excluded from default runs) and skip themselves when their environment
variables are absent, so a partially-configured environment runs whatever it can.

Set ``KEYCHAIN_INTEGRATION_REQUIRE_RUN=1`` (as CI and ``just py-test-integration``
do) to fail when the flow the run asked for never executed: the backend named by
``KEYCHAIN_INTEGRATION_BACKEND``, or the local Vault flow for a full-directory
run. Skipping is only acceptable for backends the run did not ask for.
"""

import asyncio
import base64
import contextlib
import os
import time
from typing import Any

import httpx
import pytest
from solders.hash import Hash
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

from solana_keychain.core import signed_message_bytes
from solana_keychain.core.signer import SendingSigner, SolanaSigner, TransactionSigner

REQUIRE_RUN_ENV = "KEYCHAIN_INTEGRATION_REQUIRE_RUN"
BACKEND_ENV = "KEYCHAIN_INTEGRATION_BACKEND"
VAULT_TEST_MODULE = "test_vault_integration.py"
DEFAULT_RPC_URL = "https://api.devnet.solana.com"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail runs that skipped the flow they were asked to exercise.

    A session-wide pass count is not enough: one configured backend passing would
    mask the requested one being skipped entirely. So the check is scoped: a
    single-backend run must have passed a test for that backend, and a full run
    (the ``just`` recipe, which stands up Vault itself) must have passed a Vault
    test. Other backends stay free to skip when unconfigured.
    """
    if os.environ.get(REQUIRE_RUN_ENV) != "1" or exitstatus != 0:
        return
    if session.testscollected == 0:
        return

    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    passed_node_ids = (
        [report.nodeid for report in reporter.stats.get("passed", [])] if reporter else []
    )

    backend = os.environ.get(BACKEND_ENV, "")
    if backend:
        required, scope = f"[{backend}]", f"backend {backend}"
    else:
        required, scope = f"{VAULT_TEST_MODULE}::", "the local Vault flow"

    if any(required in node_id for node_id in passed_node_ids):
        return

    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    if reporter:
        reporter.write_line(
            f"{REQUIRE_RUN_ENV}=1 but no test exercised {scope}: its environment "
            "is not configured (other backends skipping is expected)",
            red=True,
        )


def require_env(*names: str) -> dict[str, str]:
    values = {name: os.environ.get(name, "") for name in names}
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        pytest.skip(f"integration env not set: {', '.join(missing)}")
    return values


def optional_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


async def assert_message_roundtrip(signer: SolanaSigner) -> None:
    message = b"solana-keychain integration test message"
    signature = await signer.sign_message(message)
    assert signature.verify(signer.pubkey, message)


async def rpc_call(method: str, params: list[Any]) -> Any:
    rpc_url = os.environ.get("SOLANA_RPC_URL", DEFAULT_RPC_URL)
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            rpc_url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        )
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        raise AssertionError(f"{method} RPC error: {body['error']}")
    return body["result"]


async def fetch_latest_blockhash() -> Hash:
    """A live blockhash is required: services reject or silently replace a stale one,
    and a replaced blockhash changes the message bytes the signature must cover."""
    result = await rpc_call("getLatestBlockhash", [{"commitment": "finalized"}])
    return Hash.from_string(result["value"]["blockhash"])


async def unsigned_transfer(
    payer: Pubkey, recipient: Pubkey, lamports: int
) -> VersionedTransaction:
    instruction = transfer(
        TransferParams(from_pubkey=payer, to_pubkey=recipient, lamports=lamports)
    )
    message = Message.new_with_blockhash([instruction], payer, await fetch_latest_blockhash())
    return VersionedTransaction.from_legacy(Transaction.new_unsigned(message))


async def broadcast_transaction(encoded_transaction: str) -> str:
    """Returns the transaction signature the cluster accepted."""
    # Preflight defaults to finalized, which cannot yet see a blockhash stamped
    # seconds ago and rejects the send as BlockhashNotFound.
    signature = await rpc_call(
        "sendTransaction",
        [encoded_transaction, {"encoding": "base64", "preflightCommitment": "processed"}],
    )
    return str(signature)


async def confirm_transaction(
    signature: str, rebroadcast: str | None = None, timeout_seconds: float = 60.0
) -> None:
    """Poll until ``signature`` is confirmed. ``rebroadcast`` carries the encoded
    transaction when the caller owns the broadcast, and is None when the provider
    pushed it and the wire bytes are not available."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = (
            await rpc_call(
                "getSignatureStatuses", [[signature], {"searchTransactionHistory": True}]
            )
        )["value"][0]
        if status is not None:
            if status["err"] is not None:
                raise AssertionError(f"transaction failed on chain: {status['err']}")
            if status["confirmationStatus"] in ("confirmed", "finalized"):
                return
        if rebroadcast is not None:
            # A sent transaction can be dropped before it lands, and only a resend
            # while its blockhash is still valid gets it back into a block.
            with contextlib.suppress(Exception):
                await broadcast_transaction(rebroadcast)
        await asyncio.sleep(2)
    raise AssertionError(f"timed out waiting for confirmation of {signature}")


async def _unsigned_transaction(signer: SolanaSigner) -> VersionedTransaction:
    message = Message.new_with_blockhash([], signer.pubkey, await fetch_latest_blockhash())
    return VersionedTransaction.from_legacy(Transaction.new_unsigned(message))


async def assert_transaction_roundtrip(signer: SolanaSigner) -> None:
    """An instruction-free transaction keeps this focused on remote signing rather
    than balances or program execution.
    """
    assert isinstance(signer, TransactionSigner)
    transaction = await _unsigned_transaction(signer)
    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert len(bytes(result.signature)) == 64
    assert Transaction.from_bytes(base64.b64decode(result.encoded_transaction))
    assert result.signature.verify(signer.pubkey, signed_message_bytes(transaction.message))


async def assert_send_transaction_roundtrip(signer: SolanaSigner) -> None:
    """Broadcast-managed services rewrite the transaction before signing and
    execute it themselves, so the returned signature covers their bytes rather
    than the caller's and only its shape can be checked. Each signer verifies the
    signature against the bytes it actually covers internally.
    """
    assert isinstance(signer, SendingSigner)
    transaction = await _unsigned_transaction(signer)
    signature = await signer.sign_and_send_transaction(transaction)

    assert len(bytes(signature)) == 64
