"""Shared plumbing for the live integration suite.

Every test here talks to a real service. Tests are gated by the ``integration``
marker (excluded from default runs) and skip themselves when their environment
variables are absent, so a partially-configured environment runs whatever it can.
"""

import os

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from solana_keychain.core.signer import SolanaSigner
from tests.util import create_test_transaction


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


async def assert_transaction_roundtrip(signer: SolanaSigner) -> None:
    transaction = create_test_transaction(signer.pubkey, to_pubkey=_burner_recipient())
    result = await signer.sign_transaction(transaction)
    assert result.is_complete
    assert result.signature.verify(signer.pubkey, transaction.message_data())


def _burner_recipient() -> Pubkey:
    return Keypair().pubkey()
