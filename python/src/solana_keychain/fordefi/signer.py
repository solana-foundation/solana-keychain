"""Fordefi MPC custody API signer integration.

Transaction signing is asynchronous: submit via POST, then poll GET until the
MPC signing completes. Every POST carries an ECDSA P-256 request-level
signature in the ``x-signature`` header.
"""

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
)
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    get_signing_keypair_position,
    serialize_transaction,
)
from solana_keychain.fordefi.request_signer import FordefiRequestSigner, PemRequestSigner

DEFAULT_API_BASE_URL = "https://api.fordefi.com"
DEFAULT_POLL_INTERVAL_MS = 2000
DEFAULT_MAX_POLL_ATTEMPTS = 50
SUPPORTED_CHAINS = ("solana_devnet", "solana_mainnet")

_AVAILABILITY_TIMEOUT_SECONDS = 5.0
_VAULT_VERIFICATION_TIMEOUT_SECONDS = 10.0

_PUSHABLE_SUCCESS_STATES = frozenset({"completed"})
_NON_PUSHABLE_SUCCESS_STATES = frozenset({"signed", "completed"})
_TERMINAL_FAILURE_STATES = frozenset(
    {
        "aborted",
        "cancelled",
        "completed_reverted",
        "dropped",
        "error_pushing_to_blockchain",
        "error_signing",
        "insufficient_funds",
        "mined_reverted",
    }
)


def _timestamp_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class FordefiSignerConfig:
    """Configuration for a Fordefi signer.

    Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    key in ``private_key_pem``, or a custom ``FordefiRequestSigner`` in
    ``request_signer`` for KMS/HSM-backed request signing.

    ``chain`` (``solana_devnet`` / ``solana_mainnet``) switches from black-box
    raw signing to Fordefi's native Solana API types: transactions are signed
    and auto-broadcast by Fordefi, messages use ``solana_message``.

    ``fee`` is the native-mode fee configuration passed through verbatim,
    e.g. ``{"type": "priority", "priority_level": "medium"}`` or
    ``{"type": "custom", "priority_fee": "1000"}``. Requires ``chain``.
    """

    access_token: str = field(repr=False)
    vault_id: str
    public_key: str
    private_key_pem: str | None = field(default=None, repr=False)
    request_signer: FordefiRequestSigner | None = field(default=None, repr=False)
    api_base_url: str = DEFAULT_API_BASE_URL
    poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS
    max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS
    chain: str | None = None
    fee: dict[str, Any] | None = None
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class FordefiSigner(SolanaSigner):
    """Signer backed by a Fordefi vault.

    ``init()`` must be awaited before use — it fetches the vault from Fordefi
    and verifies that the configured ``public_key`` actually belongs to
    ``vault_id``. ``create_fordefi_signer()`` does this for you.

    Black-box mode (default) signs the caller's exact message bytes and the
    caller broadcasts. Native mode (``chain`` set) lets Fordefi replace the
    blockhash and fees, sign, and auto-broadcast; see ``sign_transaction``.
    """

    def __init__(self, config: FordefiSignerConfig) -> None:
        if not config.access_token:
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "access_token must not be empty")
        if not config.vault_id:
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "vault_id must not be empty")
        if not config.public_key:
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "public_key must not be empty")
        if config.private_key_pem is not None and config.request_signer is not None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "provide exactly one of private_key_pem or request_signer, not both",
            )
        if config.private_key_pem is None and config.request_signer is None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "one of private_key_pem or request_signer must be provided",
            )
        if config.chain is not None and config.chain not in SUPPORTED_CHAINS:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                f"chain must be one of {', '.join(SUPPORTED_CHAINS)}",
            )
        if config.fee is not None and config.chain is None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "fee requires chain to be set (native Solana mode)"
            )
        if config.max_poll_attempts < 1:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "max_poll_attempts must be a positive integer"
            )
        if config.poll_interval_ms < 0:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "poll_interval_ms must be a non-negative integer"
            )

        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._access_token = config.access_token
        self._vault_id = config.vault_id
        self._request_signer = (
            config.request_signer
            if config.request_signer is not None
            else PemRequestSigner(config.private_key_pem or "")
        )
        self._poll_interval_ms = config.poll_interval_ms
        self._max_poll_attempts = config.max_poll_attempts
        self._chain = config.chain
        self._fee = config.fee
        self._http_client = config.http_client
        try:
            self._public_key = Pubkey.from_string(config.public_key)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid Solana public key format"
            ) from None

    def __repr__(self) -> str:
        return f"FordefiSigner(pubkey={self._public_key}, vault_id={self._vault_id})"

    async def init(self) -> None:
        """Verify that the configured public key belongs to the configured vault.

        Without this check a valid-but-wrong address would pass configuration
        and later be returned by ``pubkey``, creating a funds-routing risk.
        """
        vault = await self._fetch_vault(_VAULT_VERIFICATION_TIMEOUT_SECONDS)
        remote_public_key = self._vault_public_key(vault)
        if remote_public_key != self._public_key:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                f"Configured public_key does not match Fordefi vault {self._vault_id}",
            )

    @property
    def pubkey(self) -> Pubkey:
        return self._public_key

    async def _sign_request(self, path: str, timestamp: int, body: str) -> str:
        return await self._request_signer.sign_request(f"{path}|{timestamp}|{body}".encode())

    async def _get_json(
        self, path: str, timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS
    ) -> Any:
        return await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Fordefi",
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout_seconds=timeout_seconds,
            client=self._http_client,
        )

    async def _post_transaction(self, request: dict[str, Any]) -> str:
        path = "/api/v1/transactions"
        body = json.dumps(request, separators=(",", ":"))
        timestamp = _timestamp_ms()
        signature = await self._sign_request(path, timestamp, body)
        response = await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Fordefi",
            method="POST",
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
                "x-signature": signature,
                "x-timestamp": str(timestamp),
            },
            content=body.encode(),
            client=self._http_client,
        )
        transaction_id = response.get("id") if isinstance(response, dict) else None
        if not isinstance(transaction_id, str):
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
        return transaction_id

    def _black_box_request(self, data: bytes) -> dict[str, Any]:
        return {
            "vault_id": self._vault_id,
            "signer_type": "api_signer",
            "sign_mode": "auto",
            "type": "black_box_signature",
            "details": {
                "format": "hash_binary",
                "hash_binary": base64.b64encode(data).decode("ascii"),
            },
        }

    def _solana_transaction_request(self, data: bytes) -> dict[str, Any]:
        details: dict[str, Any] = {
            "type": "solana_serialized_transaction_message",
            "chain": self._chain,
            "data": base64.b64encode(data).decode("ascii"),
            "push_mode": "auto",
        }
        if self._fee is not None:
            details["fee"] = self._fee
        return {
            "vault_id": self._vault_id,
            "signer_type": "api_signer",
            "sign_mode": "auto",
            "type": "solana_transaction",
            "details": details,
        }

    def _solana_message_request(self, data: bytes) -> dict[str, Any]:
        return {
            "vault_id": self._vault_id,
            "signer_type": "api_signer",
            "sign_mode": "auto",
            "type": "solana_message",
            "details": {
                "type": "personal_message_type",
                "chain": self._chain,
                "raw_data": base64.b64encode(data).decode("ascii"),
            },
        }

    async def _poll_for_result(self, transaction_id: str, *, pushable: bool) -> dict[str, Any]:
        success_states = _PUSHABLE_SUCCESS_STATES if pushable else _NON_PUSHABLE_SUCCESS_STATES
        for attempt in range(self._max_poll_attempts):
            response = await self._get_json(
                f"/api/v1/transactions/{quote(transaction_id, safe='')}"
            )
            if not isinstance(response, dict):
                raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
            state = response.get("state")
            if state in success_states:
                return response
            if state in _TERMINAL_FAILURE_STATES:
                raise SignerError(
                    SignerErrorCode.SIGNING_FAILED,
                    f"Transaction {transaction_id} reached terminal state: {state}",
                )
            if attempt + 1 < self._max_poll_attempts:
                await asyncio.sleep(self._poll_interval_ms / 1000)
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"Polling timeout after {self._max_poll_attempts} attempts",
        )

    @staticmethod
    def _extract_signature(response: dict[str, Any]) -> Signature:
        signatures = response.get("signatures")
        first = signatures[0] if isinstance(signatures, list) and signatures else None
        data = first.get("data") if isinstance(first, dict) else None
        if not isinstance(data, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Transaction signed but no signatures in response",
            )
        try:
            signature_bytes = base64.b64decode(data, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode signature base64"
            ) from None
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Expected {ED25519_SIGNATURE_LENGTH}-byte Ed25519 signature, "
                f"got {len(signature_bytes)}",
            )
        return Signature.from_bytes(signature_bytes)

    async def _sign_black_box(self, data: bytes) -> Signature:
        transaction_id = await self._post_transaction(self._black_box_request(data))
        result = await self._poll_for_result(transaction_id, pushable=False)
        return self._extract_signature(result)

    def _verify_signature(self, signature: Signature, message: bytes) -> None:
        if not signature.verify(self._public_key, message):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Signature verification failed — the returned signature does not match "
                "the public key",
            )

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        """Sign ``transaction`` via Fordefi MPC.

        Black-box mode signs the exact message bytes, places the signature in
        ``transaction`` in place, and returns the encoded transaction for the
        caller to broadcast.

        Native mode (``chain`` set) submits the message for signing with
        ``push_mode: auto``: Fordefi replaces the blockhash (and optionally
        fees), signs, and broadcasts the transaction itself. The returned
        ``encoded_transaction`` is therefore empty and ``transaction`` is left
        unmodified — the returned signature identifies the on-chain
        transaction. Only legacy transactions whose sole required signer is
        the configured vault are supported.
        """
        if self._chain is not None:
            return await self._sign_transaction_native(transaction)
        message_data = transaction.message_data()
        signature = await self._sign_black_box(message_data)
        self._verify_signature(signature, message_data)
        add_signature_to_transaction(transaction, self._public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    def _require_sole_required_signer(self, transaction: Transaction) -> None:
        account_keys = transaction.message.account_keys
        if transaction.message.header.num_required_signatures != 1 or (
            not account_keys or account_keys[0] != self._public_key
        ):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native auto-broadcast currently supports only transactions "
                "whose sole required signer is the configured vault",
            )

    async def _sign_transaction_native(self, transaction: Transaction) -> SignedTransaction:
        self._require_sole_required_signer(transaction)
        transaction_id = await self._post_transaction(
            self._solana_transaction_request(transaction.message_data())
        )
        result = await self._poll_for_result(transaction_id, pushable=True)
        raw_transaction = result.get("raw_transaction")
        if not isinstance(raw_transaction, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi solana_transaction response missing raw_transaction",
            )
        try:
            wire_bytes = base64.b64decode(raw_transaction, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode raw_transaction base64"
            ) from None
        try:
            returned = Transaction.from_bytes(wire_bytes)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to deserialize Fordefi wire transaction "
                "(versioned/v0 transactions are not supported, only legacy)",
            ) from None
        position = get_signing_keypair_position(returned, self._public_key)
        signatures = returned.signatures
        if position >= len(signatures):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi signature slot missing from returned transaction",
            )
        signature = signatures[position]
        self._verify_signature(signature, returned.message_data())
        return classify_signed_transaction(returned, "", signature)

    async def sign_message(self, message: bytes) -> Signature:
        if self._chain is not None:
            transaction_id = await self._post_transaction(self._solana_message_request(message))
            result = await self._poll_for_result(transaction_id, pushable=False)
            signature = self._extract_signature(result)
        else:
            signature = await self._sign_black_box(message)
        self._verify_signature(signature, message)
        return signature

    async def _fetch_vault(self, timeout_seconds: float) -> dict[str, Any]:
        response = await self._get_json(
            f"/api/v1/vaults/{quote(self._vault_id, safe='')}", timeout_seconds
        )
        if not isinstance(response, dict):
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
        return response

    @staticmethod
    def _vault_public_key(vault: dict[str, Any]) -> Pubkey:
        """The authoritative Solana public key of a Fordefi vault.

        Chain-specific vaults expose a base58 ``address``; black-box vaults
        expose the same 32-byte Ed25519 key as base64 ``public_key_compressed``.
        """
        address = vault.get("address")
        if isinstance(address, str) and address:
            try:
                return Pubkey.from_string(address)
            except Exception:
                raise SignerError(
                    SignerErrorCode.INVALID_PUBLIC_KEY,
                    "Fordefi vault returned an invalid Solana address",
                ) from None
        compressed = vault.get("public_key_compressed")
        if not isinstance(compressed, str):
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "Fordefi vault response included neither address nor public_key_compressed; "
                "cannot verify public_key ownership",
            )
        try:
            key_bytes = base64.b64decode(compressed, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode Fordefi vault public_key_compressed as base64",
            ) from None
        if len(key_bytes) != 32:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                "Fordefi vault public_key_compressed must decode to 32 bytes",
            )
        return Pubkey.from_bytes(key_bytes)

    async def is_available(self) -> bool:
        """Readiness probe: the vault is reachable with the bearer token and the
        request signer can produce an ``x-signature`` value."""

        async def probe() -> None:
            await self._fetch_vault(_AVAILABILITY_TIMEOUT_SECONDS)
            await self._sign_request("/api/v1/vaults", _timestamp_ms(), "")

        try:
            await asyncio.wait_for(probe(), timeout=_AVAILABILITY_TIMEOUT_SECONDS)
        except Exception:
            return False
        return True


async def create_fordefi_signer(config: FordefiSignerConfig) -> FordefiSigner:
    """Create a ready-to-use Fordefi signer (awaits ``init()``)."""
    signer = FordefiSigner(config)
    await signer.init()
    return signer
