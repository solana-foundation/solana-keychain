"""Live integration tests for the remote backends, driven by the same environment
variables as the repo's other integration suites. Each backend skips itself when
its variables are absent.

``KEYCHAIN_INTEGRATION_BACKEND`` restricts the run to a single backend (used by
the CI matrix). Selection deliberately avoids ``pytest -k``: a ``-k`` expression
substring-matches marker keywords, and every test here carries ``parametrize``.
"""

import base64
import os

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import MessageV0
from solders.signature import Signature
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.transaction import VersionedTransaction

from solana_keychain.core import signed_message_bytes
from solana_keychain.core.signer import SolanaSigner
from tests.integration.conftest import (
    assert_message_roundtrip,
    assert_transaction_roundtrip,
    optional_env,
    require_env,
)

pytestmark = pytest.mark.integration


async def make_aws_kms_signer() -> SolanaSigner:
    from solana_keychain.aws_kms import AwsKmsSignerConfig, create_aws_kms_signer

    env = require_env("AWS_KMS_KEY_ID", "AWS_KMS_SIGNER_PUBKEY")
    return await create_aws_kms_signer(
        AwsKmsSignerConfig(
            key_id=env["AWS_KMS_KEY_ID"],
            public_key=env["AWS_KMS_SIGNER_PUBKEY"],
            region=optional_env("AWS_KMS_REGION") or None,
        )
    )


async def make_gcp_kms_signer() -> SolanaSigner:
    from solana_keychain.gcp_kms import GcpKmsSignerConfig, create_gcp_kms_signer

    env = require_env("GCP_KMS_KEY_NAME", "GCP_KMS_SIGNER_PUBKEY")
    return await create_gcp_kms_signer(
        GcpKmsSignerConfig(
            key_name=env["GCP_KMS_KEY_NAME"], public_key=env["GCP_KMS_SIGNER_PUBKEY"]
        )
    )


async def make_turnkey_signer() -> SolanaSigner:
    from solana_keychain.turnkey import TurnkeySignerConfig, create_turnkey_signer
    from solana_keychain.turnkey.signer import DEFAULT_API_BASE_URL

    env = require_env(
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_PRIVATE_KEY_ID",
        "TURNKEY_PUBLIC_KEY",
    )
    return await create_turnkey_signer(
        TurnkeySignerConfig(
            api_public_key=env["TURNKEY_API_PUBLIC_KEY"],
            api_private_key=env["TURNKEY_API_PRIVATE_KEY"],
            organization_id=env["TURNKEY_ORGANIZATION_ID"],
            private_key_id=env["TURNKEY_PRIVATE_KEY_ID"],
            public_key=env["TURNKEY_PUBLIC_KEY"],
            api_base_url=optional_env("TURNKEY_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_privy_signer() -> SolanaSigner:
    from solana_keychain.privy import (
        PrivyAuthorizationContext,
        PrivySignerConfig,
        create_privy_signer,
    )
    from solana_keychain.privy.signer import DEFAULT_API_BASE_URL

    env = require_env("PRIVY_APP_ID", "PRIVY_APP_SECRET", "PRIVY_WALLET_ID")
    authorization_key = optional_env("PRIVY_AUTHORIZATION_PRIVATE_KEY")
    authorization_context = (
        PrivyAuthorizationContext(authorization_private_keys=[authorization_key])
        if authorization_key
        else None
    )
    return await create_privy_signer(
        PrivySignerConfig(
            app_id=env["PRIVY_APP_ID"],
            app_secret=env["PRIVY_APP_SECRET"],
            wallet_id=env["PRIVY_WALLET_ID"],
            api_base_url=optional_env("PRIVY_API_BASE_URL") or DEFAULT_API_BASE_URL,
            authorization_context=authorization_context,
        )
    )


async def make_para_signer() -> SolanaSigner:
    from solana_keychain.para import ParaSignerConfig, create_para_signer
    from solana_keychain.para.signer import DEFAULT_API_BASE_URL

    env = require_env("PARA_API_KEY", "PARA_WALLET_ID")
    return await create_para_signer(
        ParaSignerConfig(
            api_key=env["PARA_API_KEY"],
            wallet_id=env["PARA_WALLET_ID"],
            api_base_url=optional_env("PARA_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_fireblocks_signer() -> SolanaSigner:
    from solana_keychain.fireblocks import FireblocksSignerConfig, create_fireblocks_signer
    from solana_keychain.fireblocks.signer import DEFAULT_API_BASE_URL

    env = require_env(
        "FIREBLOCKS_API_KEY", "FIREBLOCKS_PRIVATE_KEY_PEM", "FIREBLOCKS_VAULT_ACCOUNT_ID"
    )
    return await create_fireblocks_signer(
        FireblocksSignerConfig(
            api_key=env["FIREBLOCKS_API_KEY"],
            private_key_pem=env["FIREBLOCKS_PRIVATE_KEY_PEM"],
            vault_account_id=env["FIREBLOCKS_VAULT_ACCOUNT_ID"],
            # Test vaults hold devnet assets; the library default is mainnet SOL.
            asset_id=optional_env("FIREBLOCKS_ASSET_ID") or "SOL_TEST",
            api_base_url=optional_env("FIREBLOCKS_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_fordefi_signer() -> SolanaSigner:
    from solana_keychain.fordefi import FordefiSignerConfig, create_fordefi_signer
    from solana_keychain.fordefi.signer import DEFAULT_API_BASE_URL

    env = require_env(
        "FORDEFI_ACCESS_TOKEN",
        "FORDEFI_BB_VAULT_ID",
        "FORDEFI_BB_PUBLIC_KEY",
        "FORDEFI_PRIVATE_KEY_PEM",
    )
    return await create_fordefi_signer(
        FordefiSignerConfig(
            access_token=env["FORDEFI_ACCESS_TOKEN"],
            vault_id=env["FORDEFI_BB_VAULT_ID"],
            public_key=env["FORDEFI_BB_PUBLIC_KEY"],
            private_key_pem=env["FORDEFI_PRIVATE_KEY_PEM"],
            api_base_url=optional_env("FORDEFI_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_fordefi_manual_signer() -> SolanaSigner:
    from solana_keychain.fordefi import FordefiSignerConfig, create_fordefi_signer
    from solana_keychain.fordefi.signer import DEFAULT_API_BASE_URL

    env = require_env(
        "FORDEFI_ACCESS_TOKEN",
        "FORDEFI_VAULT_ID",
        "FORDEFI_PUBLIC_KEY",
        "FORDEFI_PRIVATE_KEY_PEM",
    )
    return await create_fordefi_signer(
        FordefiSignerConfig(
            access_token=env["FORDEFI_ACCESS_TOKEN"],
            vault_id=env["FORDEFI_VAULT_ID"],
            public_key=env["FORDEFI_PUBLIC_KEY"],
            private_key_pem=env["FORDEFI_PRIVATE_KEY_PEM"],
            api_base_url=optional_env("FORDEFI_API_BASE_URL") or DEFAULT_API_BASE_URL,
            chain=optional_env("FORDEFI_CHAIN") or "solana_devnet",
            poll_interval_ms=1000,
            max_poll_attempts=110,
            push_mode="manual",
        )
    )


async def make_cdp_signer() -> SolanaSigner:
    from solana_keychain.cdp import CdpSignerConfig, create_cdp_signer

    env = require_env(
        "CDP_API_KEY_ID", "CDP_API_KEY_SECRET", "CDP_WALLET_SECRET", "CDP_SOLANA_ADDRESS"
    )
    return await create_cdp_signer(
        CdpSignerConfig(
            api_key_id=env["CDP_API_KEY_ID"],
            api_key_secret=env["CDP_API_KEY_SECRET"],
            wallet_secret=env["CDP_WALLET_SECRET"],
            address=env["CDP_SOLANA_ADDRESS"],
        )
    )


async def make_dfns_signer() -> SolanaSigner:
    from solana_keychain.dfns import DfnsSignerConfig, create_dfns_signer
    from solana_keychain.dfns.signer import DEFAULT_API_BASE_URL

    env = require_env("DFNS_AUTH_TOKEN", "DFNS_CRED_ID", "DFNS_PRIVATE_KEY_PEM", "DFNS_WALLET_ID")
    return await create_dfns_signer(
        DfnsSignerConfig(
            auth_token=env["DFNS_AUTH_TOKEN"],
            cred_id=env["DFNS_CRED_ID"],
            private_key_pem=env["DFNS_PRIVATE_KEY_PEM"],
            wallet_id=env["DFNS_WALLET_ID"],
            api_base_url=optional_env("DFNS_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_crossmint_signer() -> SolanaSigner:
    from solana_keychain.crossmint import CrossmintSignerConfig, create_crossmint_signer
    from solana_keychain.crossmint.signer import DEFAULT_API_BASE_URL

    env = require_env("CROSSMINT_API_KEY", "CROSSMINT_WALLET_LOCATOR")
    return await create_crossmint_signer(
        CrossmintSignerConfig(
            api_key=env["CROSSMINT_API_KEY"],
            wallet_locator=env["CROSSMINT_WALLET_LOCATOR"],
            signer_secret=optional_env("CROSSMINT_SIGNER_SECRET") or None,
            signer=optional_env("CROSSMINT_SIGNER") or None,
            api_base_url=optional_env("CROSSMINT_API_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_openfort_signer() -> SolanaSigner:
    from solana_keychain.openfort import OpenfortSignerConfig, create_openfort_signer
    from solana_keychain.openfort.signer import DEFAULT_API_BASE_URL

    env = require_env("OPENFORT_SECRET_KEY", "OPENFORT_ACCOUNT_ID", "OPENFORT_WALLET_SECRET")
    return await create_openfort_signer(
        OpenfortSignerConfig(
            secret_key=env["OPENFORT_SECRET_KEY"],
            account_id=env["OPENFORT_ACCOUNT_ID"],
            wallet_secret=env["OPENFORT_WALLET_SECRET"],
            api_base_url=optional_env("OPENFORT_BASE_URL") or DEFAULT_API_BASE_URL,
        )
    )


async def make_utila_signer() -> SolanaSigner:
    from solana_keychain.utila import UtilaSignerConfig, create_utila_signer
    from solana_keychain.utila.signer import (
        DEFAULT_API_BASE_URL,
        DEFAULT_MAX_POLL_ATTEMPTS,
        DEFAULT_POLL_INTERVAL_MS,
    )

    env = require_env(
        "UTILA_SERVICE_ACCOUNT_EMAIL",
        "UTILA_SERVICE_ACCOUNT_PRIVATE_KEY",
        "UTILA_VAULT_ID",
        "UTILA_WALLET_ID",
        "UTILA_NETWORK",
    )
    return await create_utila_signer(
        UtilaSignerConfig(
            service_account_email=env["UTILA_SERVICE_ACCOUNT_EMAIL"],
            service_account_private_key_pem=env["UTILA_SERVICE_ACCOUNT_PRIVATE_KEY"],
            vault_id=env["UTILA_VAULT_ID"],
            wallet_id=env["UTILA_WALLET_ID"],
            network=env["UTILA_NETWORK"],
            api_base_url=optional_env("UTILA_API_BASE_URL") or DEFAULT_API_BASE_URL,
            poll_interval_ms=int(
                optional_env("UTILA_POLL_INTERVAL_MS") or DEFAULT_POLL_INTERVAL_MS
            ),
            max_poll_attempts=int(
                optional_env("UTILA_MAX_POLL_ATTEMPTS") or DEFAULT_MAX_POLL_ATTEMPTS
            ),
        )
    )


_MESSAGE_CAPABLE = {
    "aws-kms": make_aws_kms_signer,
    "gcp-kms": make_gcp_kms_signer,
    "turnkey": make_turnkey_signer,
    "privy": make_privy_signer,
    "para": make_para_signer,
    "fireblocks": make_fireblocks_signer,
    "fordefi": make_fordefi_signer,
    "cdp": make_cdp_signer,
    "dfns": make_dfns_signer,
    "openfort": make_openfort_signer,
}

# Crossmint and Utila sign transactions only.
_TRANSACTION_ONLY = {
    "crossmint": make_crossmint_signer,
    "utila": make_utila_signer,
}


_ALL_BACKENDS = _MESSAGE_CAPABLE | _TRANSACTION_ONLY

_SELECTED_BACKEND = os.environ.get("KEYCHAIN_INTEGRATION_BACKEND", "")


def _skip_unless_selected(backend: str) -> None:
    if _SELECTED_BACKEND and backend != _SELECTED_BACKEND:
        pytest.skip(f"KEYCHAIN_INTEGRATION_BACKEND={_SELECTED_BACKEND} excludes {backend}")


@pytest.mark.parametrize("backend", sorted(_MESSAGE_CAPABLE))
async def test_live_sign_message(backend: str) -> None:
    _skip_unless_selected(backend)
    signer = await _MESSAGE_CAPABLE[backend]()
    await assert_message_roundtrip(signer)


# Broadcast-managed services rewrite the transaction before signing, so their
# signature covers their bytes rather than the caller's.
_REWRITES_TRANSACTION = frozenset({"crossmint"})


@pytest.mark.parametrize("backend", sorted(_ALL_BACKENDS))
async def test_live_sign_transaction(backend: str) -> None:
    _skip_unless_selected(backend)
    signer = await _ALL_BACKENDS[backend]()
    await assert_transaction_roundtrip(
        signer, signs_caller_bytes=backend not in _REWRITES_TRANSACTION
    )


async def test_live_fordefi_native_manual_signs_without_broadcasting() -> None:
    _skip_unless_selected("fordefi")
    signer = await make_fordefi_manual_signer()
    assert not signer.broadcasts_transactions

    transfer = Instruction(
        SYSTEM_PROGRAM_ID,
        bytes([2, 0, 0, 0]) + (0).to_bytes(8, "little"),
        [
            AccountMeta(signer.pubkey, is_signer=True, is_writable=True),
            AccountMeta(signer.pubkey, is_signer=False, is_writable=True),
        ],
    )
    message = MessageV0.try_compile(signer.pubkey, [transfer], [], Hash.default())
    transaction = VersionedTransaction.populate(
        message, [Signature.default()] * message.header.num_required_signatures
    )
    original_wire = bytes(transaction)

    result = await signer.sign_transaction(transaction)

    assert bytes(transaction) == original_wire
    assert result.is_complete
    assert result.encoded_transaction
    assert result.transaction is not None
    assert base64.b64decode(result.encoded_transaction, validate=True) == bytes(result.transaction)
    assert result.signature.verify(signer.pubkey, signed_message_bytes(result.transaction.message))
    # Intentionally no RPC submission: this test verifies sign-without-send only.


@pytest.mark.parametrize("backend", sorted(_ALL_BACKENDS))
async def test_live_is_available(backend: str) -> None:
    _skip_unless_selected(backend)
    signer = await _ALL_BACKENDS[backend]()
    assert await signer.is_available()
