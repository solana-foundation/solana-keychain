"""Vault integration tests against a local ``vault server -dev`` instance with the
shared transit test key restored (see ``just py-test-integration``)."""

import pytest

from solana_keychain import VaultSigner, VaultSignerConfig, create_vault_signer
from tests.integration.conftest import (
    assert_message_roundtrip,
    assert_transaction_roundtrip,
    require_env,
)

pytestmark = pytest.mark.integration


async def make_signer() -> VaultSigner:
    env = require_env("VAULT_ADDR", "VAULT_TOKEN", "VAULT_KEY_NAME", "VAULT_SIGNER_PUBKEY")
    return await create_vault_signer(
        VaultSignerConfig(
            vault_addr=env["VAULT_ADDR"],
            token=env["VAULT_TOKEN"],
            key_name=env["VAULT_KEY_NAME"],
            pubkey=env["VAULT_SIGNER_PUBKEY"],
        )
    )


async def test_vault_sign_message() -> None:
    await assert_message_roundtrip(await make_signer())


async def test_vault_sign_transaction() -> None:
    await assert_transaction_roundtrip(await make_signer())


async def test_vault_is_available() -> None:
    assert await (await make_signer()).is_available()
