import importlib

import httpx
import pytest
import respx
from solders.keypair import Keypair

from solana_keychain import (
    SUPPORTED_BACKENDS,
    MemorySigner,
    MemorySignerConfig,
    SignerError,
    SignerErrorCode,
    VaultSigner,
    VaultSignerConfig,
    create_keychain_signer,
)
from solana_keychain.keychain import _BACKENDS


def test_supports_all_thirteen_backends() -> None:
    assert len(SUPPORTED_BACKENDS) == 13
    assert SUPPORTED_BACKENDS == tuple(sorted(SUPPORTED_BACKENDS))


@pytest.mark.parametrize("backend", sorted(_BACKENDS))
def test_every_backend_entry_resolves(backend: str) -> None:
    module_name, config_class_name, factory_name = _BACKENDS[backend]
    module = importlib.import_module(module_name)
    assert isinstance(getattr(module, config_class_name), type)
    assert callable(getattr(module, factory_name))


async def test_dispatches_memory_backend() -> None:
    keypair = Keypair()
    signer = await create_keychain_signer("memory", MemorySignerConfig(keypair=keypair))
    assert isinstance(signer, MemorySigner)
    assert signer.pubkey == keypair.pubkey()


@respx.mock
async def test_dispatches_vault_backend() -> None:
    config = VaultSignerConfig(
        vault_addr="https://vault.example.com",
        token="test-token",
        key_name="test-key",
        pubkey=str(Keypair().pubkey()),
    )
    signer = await create_keychain_signer("vault", config)
    assert isinstance(signer, VaultSigner)


async def test_unknown_backend_is_config_error() -> None:
    with pytest.raises(SignerError) as excinfo:
        await create_keychain_signer("ledger", MemorySignerConfig(keypair=Keypair()))
    error = excinfo.value
    assert error.code == SignerErrorCode.CONFIG_ERROR


async def test_mismatched_config_is_config_error() -> None:
    with pytest.raises(SignerError) as excinfo:
        await create_keychain_signer("vault", MemorySignerConfig(keypair=Keypair()))
    assert excinfo.value.code == SignerErrorCode.CONFIG_ERROR


@respx.mock
async def test_dispatch_awaits_init_backends() -> None:
    from solana_keychain.para import ParaSignerConfig

    keypair = Keypair()
    wallet_id = "12345678-1234-1234-1234-123456789abc"
    respx.get(f"https://para.example.com/v1/wallets/{wallet_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": wallet_id,
                "type": "SOLANA",
                "status": "ACTIVE",
                "address": str(keypair.pubkey()),
            },
        )
    )
    signer = await create_keychain_signer(
        "para",
        ParaSignerConfig(
            api_key="sk_test-key",
            wallet_id=wallet_id,
            api_base_url="https://para.example.com",
        ),
    )
    assert signer.pubkey == keypair.pubkey()
