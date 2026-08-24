"""Fireblocks API signer integration."""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx
from solders.message import MessageV1
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import assert_https_url, fetch_signer_json, normalize_base_url
from solana_keychain.core.signature_util import verify_returned_signature
from solana_keychain.core.signer import (
    SignedTransaction,
    SolanaSigner,
    require_initialized,
)
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.fireblocks.jwt import create_jwt, parse_signing_key

DEFAULT_API_BASE_URL = "https://api.fireblocks.io"
DEFAULT_ASSET_ID = "SOL"
DEFAULT_POLL_INTERVAL_MS = 1000
DEFAULT_MAX_POLL_ATTEMPTS = 300


_TERMINAL_FAILURE_STATUSES = frozenset({"FAILED", "CANCELLED", "REJECTED", "BLOCKED"})
_BROADCAST_STATUSES = frozenset({"BROADCASTING", "CONFIRMING", "COMPLETED"})


@dataclass
class FireblocksSignerConfig:
    """Configuration for a Fireblocks signer.

    ``asset_id`` defaults to ``SOL`` (use ``SOL_TEST`` for devnet).

    ``use_program_call`` signs transactions with the PROGRAM_CALL operation
    instead of RAW. It is sent with ``signOnly: true`` and
    ``useDurableNonce: false``, so Fireblocks signs the submitted transaction
    without broadcasting it and without rewriting the message. The returned
    signature is verified against the vault public key over the local message
    bytes before it is used, and the caller broadcasts as in RAW mode.
    ``sign_message()`` always uses RAW, since PROGRAM_CALL only accepts
    serialized transactions.

    PROGRAM_CALL accepts legacy and v0 messages only, requires a hot wallet, and
    must be enabled for the workspace by Fireblocks.
    """

    api_key: str = field(repr=False)
    private_key_pem: str = field(repr=False)
    vault_account_id: str
    asset_id: str = DEFAULT_ASSET_ID
    api_base_url: str = DEFAULT_API_BASE_URL
    poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS
    max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS
    use_program_call: bool = False
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class FireblocksSigner(SolanaSigner):
    """Signer backed by a Fireblocks vault account using RAW or PROGRAM_CALL signing.

    ``init()`` must be awaited before use — it resolves the vault's public key.
    ``create_fireblocks_signer()`` does this for you.
    """

    def __init__(self, config: FireblocksSignerConfig) -> None:
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._api_key = config.api_key
        self._private_key_pem = config.private_key_pem
        self._signing_key = None
        try:
            self._signing_key = parse_signing_key(config.private_key_pem)
        except SignerError:
            pass
        self._vault_account_id = config.vault_account_id
        self._asset_id = config.asset_id
        self._poll_interval_ms = config.poll_interval_ms
        self._max_poll_attempts = config.max_poll_attempts
        self._use_program_call = config.use_program_call
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return (
            f"FireblocksSigner(pubkey={self._public_key}, "
            f"vault_account_id={self._vault_account_id}, asset_id={self._asset_id})"
        )

    async def init(self) -> None:
        """Resolve the vault's public key. Must be awaited before signing."""
        self._public_key = await self._fetch_public_key()

    def _initialized_pubkey(self) -> Pubkey:
        return require_initialized(self._public_key, "FireblocksSigner")

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    def _auth_headers(self, uri: str, body: str) -> dict[str, str]:
        if self._signing_key is None:
            raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "Failed to parse RSA key")
        token = create_jwt(self._api_key, self._signing_key, uri, body)
        return {"X-API-Key": self._api_key, "Authorization": f"Bearer {token}"}

    async def _get_json(self, uri: str) -> Any:
        return await fetch_signer_json(
            url=f"{self._api_base_url}{uri}",
            provider_name="Fireblocks",
            headers=self._auth_headers(uri, ""),
            client=self._http_client,
        )

    async def _fetch_public_key(self) -> Pubkey:
        uri = (
            f"/v1/vault/accounts/{quote(self._vault_account_id, safe='')}/"
            f"{quote(self._asset_id, safe='')}/addresses_paginated"
        )
        response = await self._get_json(uri)
        addresses = response.get("addresses") if isinstance(response, dict) else None
        address = self._select_vault_address(addresses if isinstance(addresses, list) else [])
        try:
            return Pubkey.from_string(address)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid public key from Fireblocks"
            ) from None

    def _select_vault_address(self, addresses: list[Any]) -> str:
        """Pick the address for the configured asset, failing on an empty or
        ambiguous response: a mistyped vault account or asset id must not yield a
        working signer bound to an unintended fee payer. Entries without an
        ``assetId`` are kept, since the endpoint is already scoped by asset.
        """
        unique: list[str] = []
        for entry in addresses:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            asset_id = entry.get("assetId")
            if not isinstance(address, str) or not address:
                continue
            if isinstance(asset_id, str) and asset_id and asset_id != self._asset_id:
                continue
            if address not in unique:
                unique.append(address)
        if len(unique) == 1:
            return unique[0]
        if not unique:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                f"Fireblocks returned no address for vault account "
                f"{self._vault_account_id} asset {self._asset_id}",
            )
        raise SignerError(
            SignerErrorCode.INVALID_PUBLIC_KEY,
            f"Fireblocks returned {len(unique)} addresses for vault account "
            f"{self._vault_account_id} asset {self._asset_id}; cannot choose a signing identity",
        )

    async def _create_transaction(self, request: dict[str, Any]) -> str:
        uri = "/v1/transactions"
        body = json.dumps(request, separators=(",", ":"))
        headers = self._auth_headers(uri, body)
        headers["Content-Type"] = "application/json"
        response = await fetch_signer_json(
            url=f"{self._api_base_url}{uri}",
            provider_name="Fireblocks",
            method="POST",
            headers=headers,
            content=body.encode(),
            client=self._http_client,
        )
        transaction_id = response.get("id") if isinstance(response, dict) else None
        if not isinstance(transaction_id, str):
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
        return transaction_id

    async def _poll_for_signature(
        self, transaction_id: str, *, program_call: bool = False
    ) -> dict[str, Any]:
        for _ in range(self._max_poll_attempts):
            response = await self._get_json(f"/v1/transactions/{quote(transaction_id, safe='')}")
            if not isinstance(response, dict):
                raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
            status = response.get("status")
            if program_call:
                if status == "SIGNED":
                    return response
                if status in _BROADCAST_STATUSES:
                    raise SignerError(
                        SignerErrorCode.BROADCAST_UNCONFIRMED,
                        f"Fireblocks broadcast the PROGRAM_CALL despite signOnly "
                        f"(status {status}); the transaction may already be executing",
                        provider_transaction_id=transaction_id,
                    )
            elif status == "COMPLETED":
                return response
            if status in _TERMINAL_FAILURE_STATUSES:
                raise SignerError(
                    SignerErrorCode.SIGNING_FAILED, f"Transaction {status}: {transaction_id}"
                )
            await asyncio.sleep(self._poll_interval_ms / 1000)
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"Transaction polling timeout after {self._max_poll_attempts} attempts - "
            "signing request may still complete",
        )

    @staticmethod
    def _extract_signature(
        response: dict[str, Any], *, allow_tx_hash_carrier: bool = False
    ) -> Signature:
        signed_messages = response.get("signedMessages")
        first = (
            signed_messages[0] if isinstance(signed_messages, list) and signed_messages else None
        )
        signature_data = first.get("signature") if isinstance(first, dict) else None
        full_sig = signature_data.get("fullSig") if isinstance(signature_data, dict) else None
        if not isinstance(full_sig, str):
            tx_hash = response.get("txHash") if allow_tx_hash_carrier else None
            if isinstance(tx_hash, str) and tx_hash:
                try:
                    return Signature.from_string(tx_hash)
                except Exception:
                    raise SignerError(
                        SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode base58 signature"
                    ) from None
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "No reusable signature found in response (no signed_messages)",
            )
        try:
            signature_bytes = bytes.fromhex(full_sig)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode hex signature"
            ) from None
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Invalid signature length (expected {ED25519_SIGNATURE_LENGTH} bytes)",
            )
        return Signature.from_bytes(signature_bytes)

    async def _sign_bytes(self, message: bytes) -> Signature:
        public_key = self._initialized_pubkey()
        transaction_id = await self._create_transaction(
            {
                "assetId": self._asset_id,
                "operation": "RAW",
                "source": {"type": "VAULT_ACCOUNT", "id": self._vault_account_id},
                "extraParameters": {"rawMessageData": {"messages": [{"content": message.hex()}]}},
            }
        )
        response = await self._poll_for_signature(transaction_id)
        signature = self._extract_signature(response)
        verify_returned_signature(signature, public_key, message)
        return signature

    async def _sign_program_call(
        self, transaction: VersionedTransaction, message: bytes
    ) -> Signature:
        """Sign a transaction with the PROGRAM_CALL operation in sign-only mode.

        Fireblocks returns the signature either in ``signedMessages`` or as the
        ``txHash`` of the signed transaction, so both carriers are accepted and
        the candidate bytes are verified before use.
        """
        public_key = self._initialized_pubkey()
        if isinstance(transaction.message, MessageV1):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fireblocks PROGRAM_CALL accepts legacy and v0 messages only; a v1 message "
                "cannot be signed in this mode",
            )
        transaction_id = await self._create_transaction(
            {
                "assetId": self._asset_id,
                "operation": "PROGRAM_CALL",
                "source": {"type": "VAULT_ACCOUNT", "id": self._vault_account_id},
                "extraParameters": {
                    "programCallData": serialize_transaction(transaction),
                    "signOnly": True,
                    "useDurableNonce": False,
                },
            }
        )
        response = await self._poll_for_signature(transaction_id, program_call=True)
        signature = self._extract_signature(response, allow_tx_hash_carrier=True)
        verify_returned_signature(signature, public_key, message)
        return signature

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        message = signed_message_bytes(transaction.message)
        signature = (
            await self._sign_program_call(transaction, message)
            if self._use_program_call
            else await self._sign_bytes(message)
        )
        add_signature_to_transaction(transaction, self._initialized_pubkey(), signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return await self._sign_bytes(message)

    async def is_available(self) -> bool:
        if self._public_key is None:
            return False
        try:
            await self._get_json(f"/v1/vault/accounts/{quote(self._vault_account_id, safe='')}")
        except SignerError:
            return False
        return True


async def create_fireblocks_signer(config: FireblocksSignerConfig) -> FireblocksSigner:
    """Create a ready-to-use Fireblocks signer (awaits ``init()``)."""
    signer = FireblocksSigner(config)
    await signer.init()
    return signer
