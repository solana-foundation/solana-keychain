"""Unified factory: create any backend's signer from a backend name and its config.

Backends are imported lazily, so backends whose dependencies live behind an
optional extra only load when requested.
"""

import importlib
from typing import Any

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SolanaSigner

_BACKENDS: dict[str, tuple[str, str, str]] = {
    "aws-kms": ("solana_keychain.aws_kms", "AwsKmsSignerConfig", "create_aws_kms_signer"),
    "cdp": ("solana_keychain.cdp", "CdpSignerConfig", "create_cdp_signer"),
    "crossmint": (
        "solana_keychain.crossmint",
        "CrossmintSignerConfig",
        "create_crossmint_signer",
    ),
    "dfns": ("solana_keychain.dfns", "DfnsSignerConfig", "create_dfns_signer"),
    "fireblocks": (
        "solana_keychain.fireblocks",
        "FireblocksSignerConfig",
        "create_fireblocks_signer",
    ),
    "gcp-kms": ("solana_keychain.gcp_kms", "GcpKmsSignerConfig", "create_gcp_kms_signer"),
    "memory": ("solana_keychain.memory", "MemorySignerConfig", "create_memory_signer"),
    "openfort": ("solana_keychain.openfort", "OpenfortSignerConfig", "create_openfort_signer"),
    "para": ("solana_keychain.para", "ParaSignerConfig", "create_para_signer"),
    "privy": ("solana_keychain.privy", "PrivySignerConfig", "create_privy_signer"),
    "turnkey": ("solana_keychain.turnkey", "TurnkeySignerConfig", "create_turnkey_signer"),
    "utila": ("solana_keychain.utila", "UtilaSignerConfig", "create_utila_signer"),
    "vault": ("solana_keychain.vault", "VaultSignerConfig", "create_vault_signer"),
}

SUPPORTED_BACKENDS = tuple(sorted(_BACKENDS))


async def create_keychain_signer(backend: str, config: Any) -> SolanaSigner:
    """Create a ready-to-use signer for ``backend`` from its config object.

    ``config`` must be the backend's own config dataclass (e.g. ``VaultSignerConfig``
    for ``"vault"``). Backends with optional-extra dependencies raise an
    ``ImportError`` naming the extra to install when it is missing.
    """
    entry = _BACKENDS.get(backend)
    if entry is None:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            f"Unknown backend {backend!r}; supported backends: {', '.join(SUPPORTED_BACKENDS)}",
        )
    module_name, config_class_name, factory_name = entry
    module = importlib.import_module(module_name)
    config_class = getattr(module, config_class_name)
    if not isinstance(config, config_class):
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            f"Backend {backend!r} requires {config_class_name}, got {type(config).__name__}",
        )
    factory = getattr(module, factory_name)
    signer: SolanaSigner = await factory(config)
    return signer
