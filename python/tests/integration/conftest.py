"""Shared plumbing for the live integration suite.

Every test here talks to a real service. Tests are gated by the ``integration``
marker (excluded from default runs) and skip themselves when their environment
variables are absent, so a partially-configured environment runs whatever it can.

Set ``KEYCHAIN_INTEGRATION_REQUIRE_RUN=1`` (as CI and ``just py-test-integration``
do) to fail the session when every selected test skipped — an all-skipped run
means the environment is misconfigured, not that the signer works.
"""

import os

import httpx
import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

from solana_keychain.core.signer import SolanaSigner

REQUIRE_RUN_ENV = "KEYCHAIN_INTEGRATION_REQUIRE_RUN"
DEFAULT_RPC_URL = "https://api.devnet.solana.com"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if os.environ.get(REQUIRE_RUN_ENV) != "1":
        return
    if exitstatus != 0 or session.testscollected == 0:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    passed = len(reporter.stats.get("passed", [])) if reporter else 0
    if passed == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        if reporter:
            reporter.write_line(
                f"{REQUIRE_RUN_ENV}=1 but every selected integration test was "
                "skipped — environment is not configured for the requested backend",
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


async def assert_transaction_roundtrip(signer: SolanaSigner) -> None:
    # An instruction-free transaction keeps this focused on remote signing rather
    # than balances or program execution.
    message = Message.new_with_blockhash([], signer.pubkey, await fetch_latest_blockhash())
    transaction = Transaction.new_unsigned(message)
    result = await signer.sign_transaction(transaction)
    assert result.is_complete
    assert result.signature.verify(signer.pubkey, transaction.message_data())


def _burner_recipient() -> Pubkey:
    return Keypair().pubkey()
