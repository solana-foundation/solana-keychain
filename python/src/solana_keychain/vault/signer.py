"""HashiCorp Vault signer integration."""

import base64
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import assert_https_url, fetch_signer_json, normalize_base_url
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
)


@dataclass
class VaultSignerConfig:
    """Configuration for a Vault transit-engine signer.

    The Vault key must be an ed25519 key created in the transit engine, e.g.
    ``vault write transit/keys/my-key type=ed25519``. ``pubkey`` is the base58
    Solana public key corresponding to that transit key.
    """

    vault_addr: str
    token: str = field(repr=False)
    key_name: str
    pubkey: str
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


def _strip_vault_signature_prefix(signature: str) -> str:
    rest = signature.removeprefix("vault:v")
    if rest == signature:
        return signature
    version, sep, encoded = rest.partition(":")
    if not sep or not version or not (version.isascii() and version.isdigit()):
        return signature
    return encoded


class VaultSigner(SolanaSigner):
    """Signer backed by the HashiCorp Vault transit engine."""

    def __init__(self, config: VaultSignerConfig) -> None:
        try:
            self._pubkey = Pubkey.from_string(config.pubkey)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Failed to decode base58 public key"
            ) from None
        vault_addr = normalize_base_url(config.vault_addr)
        assert_https_url(vault_addr, "vault_addr", allow_http_loopback_in_tests=True)
        self._vault_addr = vault_addr
        self._token = config.token
        self._key_name = config.key_name
        self._http_client = config.http_client

    def __repr__(self) -> str:
        return f"VaultSigner(pubkey={self._pubkey})"

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    async def _sign_bytes(self, payload: bytes) -> Signature:
        url = f"{self._vault_addr}/v1/transit/sign/{quote(self._key_name, safe='')}"
        result = await fetch_signer_json(
            url=url,
            provider_name="Vault",
            method="POST",
            headers={"X-Vault-Token": self._token},
            json_body={"input": base64.b64encode(payload).decode("ascii")},
            client=self._http_client,
        )
        data = result.get("data") if isinstance(result, dict) else None
        signature_b64 = data.get("signature") if isinstance(data, dict) else None
        if not isinstance(signature_b64, str):
            raise SignerError(SignerErrorCode.REMOTE_API_ERROR, "No signature in Vault response")
        try:
            signature_bytes = base64.b64decode(
                _strip_vault_signature_prefix(signature_b64), validate=True
            )
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode signature"
            ) from None
        try:
            signature = Signature.from_bytes(signature_bytes)
        except Exception:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Invalid signature format") from None
        if not signature.verify(self._pubkey, payload):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Signature verification failed — the returned signature does not match "
                "the public key",
            )
        return signature

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        signature = await self._sign_bytes(transaction.message_data())
        add_signature_to_transaction(transaction, self._pubkey, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return await self._sign_bytes(message)

    async def is_available(self) -> bool:
        url = f"{self._vault_addr}/v1/transit/keys/{quote(self._key_name, safe='')}"
        try:
            result = await fetch_signer_json(
                url=url,
                provider_name="Vault",
                method="GET",
                headers={"X-Vault-Token": self._token},
                client=self._http_client,
            )
        except SignerError:
            return False
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            return False
        return data.get("supports_signing") is True and data.get("type") == "ed25519"


async def create_vault_signer(config: VaultSignerConfig) -> VaultSigner:
    """Create a ready-to-use Vault signer."""
    return VaultSigner(config)
