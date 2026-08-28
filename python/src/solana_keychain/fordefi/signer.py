"""Fordefi MPC custody API signer integration.

Transaction signing is asynchronous: submit via POST, then poll GET until the
MPC signing completes. Every POST carries an ECDSA P-256 request-level
signature in the ``x-signature`` header.
"""

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import (
    AVAILABILITY_TIMEOUT_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
    probe_availability,
    provider_may_have_accepted,
)
from solana_keychain.core.poll import poll_attempts
from solana_keychain.core.signature_util import (
    extract_and_verify_rewritten_transaction,
    verify_returned_signature,
)
from solana_keychain.core.signer import (
    ModifyingSigner,
    SendingSigner,
    SignedTransaction,
    SolanaSigner,
    TransactionSigner,
)
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    PendingTransactionId,
    add_signature_to_transaction,
    classify_signed_transaction,
    get_signing_keypair_position,
    idempotency_key_from_message,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.fordefi.request_signer import FordefiRequestSigner, PemRequestSigner

_logger = logging.getLogger("solana_keychain")

DEFAULT_API_BASE_URL = "https://api.fordefi.com"
DEFAULT_POLL_INTERVAL_MS = 2000
DEFAULT_MAX_POLL_ATTEMPTS = 50
SUPPORTED_CHAINS = ("solana_devnet", "solana_mainnet")

FordefiPushMode = Literal["auto", "manual"]

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

    ``chain`` (``solana_devnet`` / ``solana_mainnet``) and ``push_mode`` select the
    signer type: no ``chain`` builds a ``FordefiBlackBoxSigner``; a chain with
    ``push_mode`` unset or ``auto`` builds a ``FordefiNativeAutoSigner``, where
    Fordefi signs and broadcasts; a chain with ``push_mode="manual"`` builds a
    ``FordefiNativeManualSigner``, where Fordefi signs without broadcasting.
    Native modes use Fordefi's native Solana API types, so messages go through
    ``solana_message``.

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
    push_mode: FordefiPushMode | None = None
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)
    pending_transaction_id: PendingTransactionId | None = None


class _FordefiSignerBase(SolanaSigner):
    """Shared Fordefi API plumbing: request signing, submit, polling, vault lookup.

    The configured ``public_key`` is trusted as the vault's Solana address;
    no remote lookup is performed at construction time.
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
        self._http_client = config.http_client
        self._pending_transaction_id = config.pending_transaction_id
        try:
            self._public_key = Pubkey.from_string(config.public_key)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid Solana public key format"
            ) from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pubkey={self._public_key}, vault_id={self._vault_id})"

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

    async def _post_transaction(
        self, request: dict[str, Any], idempotence_id: str | None = None
    ) -> str:
        path = "/api/v1/transactions"
        body = json.dumps(request, separators=(",", ":"))
        timestamp = _timestamp_ms()
        signature = await self._sign_request(path, timestamp, body)
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "x-signature": signature,
            "x-timestamp": str(timestamp),
        }
        if idempotence_id is not None:
            headers["x-idempotence-id"] = idempotence_id
        response = await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Fordefi",
            method="POST",
            headers=headers,
            content=body.encode(),
            client=self._http_client,
        )
        transaction_id = response.get("id") if isinstance(response, dict) else None
        if not isinstance(transaction_id, str) or not transaction_id:
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
        return transaction_id

    async def _poll_for_result(self, transaction_id: str, *, pushable: bool) -> dict[str, Any]:
        success_states = _PUSHABLE_SUCCESS_STATES if pushable else _NON_PUSHABLE_SUCCESS_STATES
        async for _ in poll_attempts(self._max_poll_attempts, self._poll_interval_ms):
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

    async def _fetch_vault(self, timeout_seconds: float) -> dict[str, Any]:
        response = await self._get_json(
            f"/api/v1/vaults/{quote(self._vault_id, safe='')}", timeout_seconds
        )
        if not isinstance(response, dict):
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse response")
        return response

    async def is_available(self) -> bool:
        """Readiness probe: the vault is reachable with the bearer token and the
        request signer can produce an ``x-signature`` value."""

        async def probe() -> bool:
            await self._fetch_vault(AVAILABILITY_TIMEOUT_SECONDS)
            await self._sign_request("/api/v1/vaults", _timestamp_ms(), "")
            return True

        return await probe_availability(probe)


class FordefiBlackBoxSigner(_FordefiSignerBase, TransactionSigner):
    """Signer backed by a Fordefi black box vault.

    Signs the caller's exact message bytes via ``black_box_signature``; Fordefi
    does not broadcast, so the caller submits the returned encoded transaction
    to an RPC. ``config.chain``, ``config.fee``, ``config.push_mode`` and
    ``config.max_priority_fee_lamports`` must be unset; they select a native
    Solana signer.
    """

    def __init__(self, config: FordefiSignerConfig) -> None:
        if config.chain is not None or config.fee is not None or config.push_mode is not None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "chain, fee and push_mode select native Solana mode; use "
                "FordefiNativeAutoSigner or FordefiNativeManualSigner",
            )
        super().__init__(config)

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

    async def _sign_black_box(self, data: bytes) -> Signature:
        transaction_id = await self._post_transaction(self._black_box_request(data))
        result = await self._poll_for_result(transaction_id, pushable=False)
        return self._extract_signature(result)

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign ``transaction`` via Fordefi MPC.

        Signs the exact message bytes, places the signature in ``transaction`` in
        place, and returns the encoded transaction for the caller to broadcast.
        """
        message_data = signed_message_bytes(transaction.message)
        signature = await self._sign_black_box(message_data)
        verify_returned_signature(signature, self._public_key, message_data)
        add_signature_to_transaction(transaction, self._public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        signature = await self._sign_black_box(message)
        verify_returned_signature(signature, self._public_key, message)
        return signature


class _FordefiNativeSignerBase(_FordefiSignerBase):
    """Shared native-mode plumbing: chain validation and the native request bodies."""

    _push_mode: FordefiPushMode

    def __init__(self, config: FordefiSignerConfig) -> None:
        if config.chain is None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "chain must be set for native Solana mode; use FordefiBlackBoxSigner without it",
            )
        if config.chain not in SUPPORTED_CHAINS:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                f"chain must be one of {', '.join(SUPPORTED_CHAINS)}",
            )
        super().__init__(config)
        self._chain = config.chain
        self._fee = config.fee

    def _solana_transaction_request(self, data: bytes) -> dict[str, Any]:
        details: dict[str, Any] = {
            "type": "solana_serialized_transaction_message",
            "chain": self._chain,
            "data": base64.b64encode(data).decode("ascii"),
            "push_mode": self._push_mode,
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

    async def sign_message(self, message: bytes) -> Signature:
        transaction_id = await self._post_transaction(self._solana_message_request(message))
        result = await self._poll_for_result(transaction_id, pushable=False)
        signature = self._extract_signature(result)
        verify_returned_signature(signature, self._public_key, message)
        return signature


class FordefiNativeAutoSigner(_FordefiNativeSignerBase, SendingSigner):
    """Signer backed by a regular Fordefi Solana vault.

    Uses Fordefi's native ``solana_transaction`` / ``solana_message`` API types
    with ``push_mode: auto``: Fordefi replaces the blockhash (and optionally
    fees), signs, and broadcasts on chain itself. ``config.chain`` must be set
    and ``config.push_mode`` must be unset or ``auto``.
    """

    _push_mode: FordefiPushMode = "auto"

    def __init__(self, config: FordefiSignerConfig) -> None:
        if config.push_mode not in (None, "auto"):
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "push_mode must be auto here; use FordefiNativeManualSigner for manual",
            )
        super().__init__(config)

    async def sign_and_send_transaction(self, transaction: VersionedTransaction) -> Signature:
        """Sign ``transaction`` and let Fordefi broadcast it.

        Submits the message for signing with ``push_mode: auto``: Fordefi
        replaces the blockhash (and optionally fees), signs, and broadcasts the
        transaction itself, so ``transaction`` is left unmodified and the
        returned signature identifies the on-chain transaction. Only legacy
        transactions whose sole required signer is the configured vault are
        supported.

        Not retry-safe: any failure after Fordefi accepts the submission raises
        ``BROADCAST_UNCONFIRMED`` carrying ``provider_transaction_id``; check
        that transaction with Fordefi before retrying. A submission that fails
        without a usable response raises ``BROADCAST_UNCONFIRMED`` with no
        ``provider_transaction_id``.

        Each create carries an ``x-idempotence-id`` derived from the message
        bytes, so replaying these exact bytes cannot create a second
        transaction; a rebuilt transaction derives a different id and is
        broadcast again.

        A cancellation cannot carry a structured error: it must be re-raised as
        ``asyncio.CancelledError``, and awaiting a cancelled task hands the
        awaiter a fresh instance without the raised message. Pass a
        ``PendingTransactionId`` as ``pending_transaction_id`` in the config and
        read it after a cancellation to recover the accepted transaction id.
        """
        signed = await self._sign_transaction_native(transaction)
        return signed.signature

    def _require_sole_required_signer(self, transaction: VersionedTransaction) -> None:
        account_keys = transaction.message.account_keys
        if transaction.message.header.num_required_signatures != 1 or (
            not account_keys or account_keys[0] != self._public_key
        ):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native auto-broadcast currently supports only transactions "
                "whose sole required signer is the configured vault",
            )

    async def _sign_transaction_native(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        self._require_sole_required_signer(transaction)
        message_data = signed_message_bytes(transaction.message)
        try:
            transaction_id = await self._post_transaction(
                self._solana_transaction_request(message_data),
                idempotence_id=idempotency_key_from_message(message_data),
            )
        except asyncio.CancelledError as error:
            # The re-raise must stay a CancelledError for asyncio, so the warning
            # goes to the log.
            _logger.warning(
                "Fordefi may have accepted a cancelled transaction with no id "
                "returned; check before retrying"
            )
            raise asyncio.CancelledError(
                "Fordefi may have accepted the transaction, but no transaction id was returned"
            ) from error
        except SignerError as error:
            if not provider_may_have_accepted(error.status_code):
                raise
            # Fordefi may be broadcasting a transaction whose id never reached us.
            raise SignerError(
                SignerErrorCode.BROADCAST_UNCONFIRMED,
                error._detail,
                status_code=error.status_code,
            ) from None
        if self._pending_transaction_id is not None:
            self._pending_transaction_id.set(transaction_id)
        try:
            signed = await self._finish_native_broadcast(transaction_id)
        except asyncio.CancelledError as error:
            # Awaiting a cancelled task strips the raised instance, so the id is
            # also logged and left in the registered slot; the re-raise must stay
            # a CancelledError for asyncio.
            _logger.warning(
                "Fordefi may have executed cancelled transaction %s; check it before retrying",
                transaction_id,
            )
            raise asyncio.CancelledError(
                "Fordefi may have executed the transaction, but the outcome could "
                f"not be confirmed (provider transaction id: {transaction_id})"
            ) from error
        except SignerError as error:
            self._clear_pending_transaction_id()
            raise SignerError(
                SignerErrorCode.BROADCAST_UNCONFIRMED,
                error._detail,
                provider_transaction_id=transaction_id,
            ) from None
        self._clear_pending_transaction_id()
        return signed

    def _clear_pending_transaction_id(self) -> None:
        if self._pending_transaction_id is not None:
            self._pending_transaction_id.clear()

    async def _finish_native_broadcast(self, transaction_id: str) -> SignedTransaction:
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
            returned = VersionedTransaction.from_bytes(wire_bytes)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to deserialize Fordefi wire transaction",
            ) from None
        position = get_signing_keypair_position(returned, self._public_key)
        signatures = returned.signatures
        if position >= len(signatures):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi signature slot missing from returned transaction",
            )
        signature = signatures[position]
        verify_returned_signature(
            signature, self._public_key, signed_message_bytes(returned.message)
        )
        return classify_signed_transaction(returned, "", signature)


class FordefiNativeManualSigner(_FordefiNativeSignerBase, ModifyingSigner):
    """Signer backed by a regular Fordefi Solana vault that does not broadcast.

    Uses Fordefi's native ``solana_transaction`` / ``solana_message`` API types
    with ``push_mode: manual``: Fordefi rewrites the blockhash and the Compute
    Budget fee instructions and signs without broadcasting, so the caller
    broadcasts the transaction Fordefi returned. ``config.chain`` must be set and
    ``config.push_mode`` must be ``manual``.
    """

    _push_mode: FordefiPushMode = "manual"

    def __init__(self, config: FordefiSignerConfig) -> None:
        if config.push_mode != "manual":
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                'push_mode must be "manual" here; use FordefiNativeAutoSigner for auto',
            )
        super().__init__(config)

    async def modify_and_sign_transaction(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        """Let Fordefi rewrite ``transaction`` and sign the rewrite.

        Submits the unsigned message with ``push_mode: manual``. Fordefi rewrites
        the blockhash and the Compute Budget fee instructions and signs without
        broadcasting. The rewrite is not diffed against what was submitted, so
        inspect ``SignedTransaction.transaction`` before broadcasting it; the
        caller's ``transaction`` is left untouched and its bytes are not the ones
        the returned signature covers.

        Fordefi must be the transaction fee payer and must sign before every
        downstream signer, so a transaction that is not vault-paid or already
        carries a signature is rejected before submitting.

        The create carries an ``x-idempotence-id`` derived from the message bytes
        under a manual-specific namespace, so it can never reuse the id of an
        auto create that did broadcast those same bytes.
        """
        self._require_unsigned_vault_paid_transaction(transaction)
        message_data = signed_message_bytes(transaction.message)
        transaction_id = await self._post_transaction(
            self._solana_transaction_request(message_data),
            idempotence_id=self._manual_idempotence_id(message_data),
        )
        result = await self._poll_for_result(transaction_id, pushable=False)
        returned, signature = extract_and_verify_rewritten_transaction(
            self._decode_raw_transaction(result), self._public_key, "Fordefi"
        )
        return classify_signed_transaction(returned, serialize_transaction(returned), signature)

    def _manual_idempotence_id(self, message_data: bytes) -> str:
        namespace = f"fordefi:solana:manual:{self._chain}:{self._vault_id}:".encode()
        return idempotency_key_from_message(namespace + message_data)

    def _require_unsigned_vault_paid_transaction(self, transaction: VersionedTransaction) -> None:
        account_keys = transaction.message.account_keys
        if not account_keys or account_keys[0] != self._public_key:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native manual signing requires the configured vault to be "
                "the transaction fee payer",
            )
        if any(signature != Signature.default() for signature in transaction.signatures):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native manual signing must run before any transaction "
                "signatures are applied",
            )

    @staticmethod
    def _decode_raw_transaction(result: dict[str, Any]) -> bytes:
        raw_transaction = result.get("raw_transaction")
        if not isinstance(raw_transaction, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi solana_transaction response missing raw_transaction",
            )
        try:
            return base64.b64decode(raw_transaction, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode raw_transaction base64"
            ) from None


async def create_fordefi_signer(
    config: FordefiSignerConfig,
) -> FordefiBlackBoxSigner | FordefiNativeAutoSigner | FordefiNativeManualSigner:
    """Create a ready-to-use Fordefi signer, picked by ``config.chain`` and
    ``config.push_mode``."""
    if config.chain is None:
        return FordefiBlackBoxSigner(config)
    if config.push_mode == "manual":
        return FordefiNativeManualSigner(config)
    return FordefiNativeAutoSigner(config)
