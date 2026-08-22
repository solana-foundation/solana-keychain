"""Shared plumbing for the live integration suite.

Every test here talks to a real service. Tests are gated by the ``integration``
marker (excluded from default runs) and skip themselves when their environment
variables are absent, so a partially-configured environment runs whatever it can.

Set ``KEYCHAIN_INTEGRATION_REQUIRE_RUN=1`` (as CI and ``just py-test-integration``
do) to fail when the flow the run asked for never executed: the backend named by
``KEYCHAIN_INTEGRATION_BACKEND``, or the local Vault flow for a full-directory
run. Skipping is only acceptable for backends the run did not ask for.
"""

import base64
import os

import httpx
import pytest
from solders.hash import Hash
from solders.message import Message
from solders.transaction import Transaction, VersionedTransaction

from solana_keychain.core import signed_message_bytes
from solana_keychain.core.signer import SolanaSigner

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


async def fetch_latest_blockhash() -> Hash:
    """A live blockhash is required: services reject or silently replace a stale one,
    and a replaced blockhash changes the message bytes the signature must cover."""
    rpc_url = os.environ.get("SOLANA_RPC_URL", DEFAULT_RPC_URL)
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [{"commitment": "finalized"}],
            },
        )
    response.raise_for_status()
    return Hash.from_string(response.json()["result"]["value"]["blockhash"])


async def assert_transaction_roundtrip(
    signer: SolanaSigner, *, signs_caller_bytes: bool = True
) -> None:
    """An instruction-free transaction keeps this focused on remote signing rather
    than balances or program execution.

    ``signs_caller_bytes=False`` for broadcast-managed services that rewrite the
    transaction before signing and broadcast it themselves: their signature covers
    their own bytes, so only its shape can be checked, and there is nothing left
    for the caller to send. Each signer verifies the signature against the bytes it
    actually covers internally.
    """
    message = Message.new_with_blockhash([], signer.pubkey, await fetch_latest_blockhash())
    transaction = VersionedTransaction.from_legacy(Transaction.new_unsigned(message))
    result = await signer.sign_transaction(transaction)

    assert result.is_complete
    assert len(bytes(result.signature)) == 64
    if signs_caller_bytes:
        assert Transaction.from_bytes(base64.b64decode(result.encoded_transaction))
        assert result.signature.verify(signer.pubkey, signed_message_bytes(transaction.message))
    else:
        assert result.encoded_transaction == ""
