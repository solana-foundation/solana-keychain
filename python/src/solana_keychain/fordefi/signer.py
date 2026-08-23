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
from solders.compute_budget import ID as COMPUTE_BUDGET_ID
from solders.instruction import CompiledInstruction
from solders.message import Message, MessageHeader, MessageV0, MessageV1
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
    provider_may_have_accepted,
)
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    get_signing_keypair_position,
    has_all_required_signatures,
    idempotency_key_from_message,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.fordefi.request_signer import FordefiRequestSigner, PemRequestSigner

_logger = logging.getLogger("solana_keychain")

DEFAULT_API_BASE_URL = "https://api.fordefi.com"
DEFAULT_POLL_INTERVAL_MS = 2000
DEFAULT_MAX_POLL_ATTEMPTS = 50

DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 100_000_000
"""Default bound on the priority fee Fordefi may introduce on its own initiative
during native manual signing, in lamports.

It applies whenever the caller has not stated a bound of their own, so a
compromised or malfunctioning API response cannot drain the fee payer. Raise it
via ``FordefiSignerConfig.max_priority_fee_lamports``.
"""
SUPPORTED_CHAINS = ("solana_devnet", "solana_mainnet")
SOLANA_PACKET_DATA_SIZE = 1232

FordefiPushMode = Literal["auto", "manual"]

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

_SET_COMPUTE_UNIT_LIMIT = 2
_SET_COMPUTE_UNIT_PRICE = 3
_MAX_COMPUTE_UNIT_LIMIT = 1_400_000
_MICRO_LAMPORTS_PER_LAMPORT = 1_000_000


@dataclass(frozen=True)
class _ManualFeeInstructions:
    limit: int | None = None
    price: int | None = None


def _message_with_recent_blockhash(message: Any, recent_blockhash: Any) -> Any:
    """Clone a supported message while replacing only its lifetime hash."""
    if isinstance(message, Message):
        header = message.header
        return Message.new_with_compiled_instructions(
            header.num_required_signatures,
            header.num_readonly_signed_accounts,
            header.num_readonly_unsigned_accounts,
            message.account_keys,
            recent_blockhash,
            message.instructions,
        )
    if isinstance(message, MessageV0):
        return MessageV0(
            message.header,
            message.account_keys,
            recent_blockhash,
            message.instructions,
            message.address_table_lookups,
        )
    if isinstance(message, MessageV1):
        return MessageV1(
            message.header,
            message.config,
            recent_blockhash,
            message.account_keys,
            message.instructions,
        )
    raise TypeError(f"Unsupported Solana message type: {type(message).__name__}")


def _normalize_manual_fee_message(
    message: Message | MessageV0,
) -> tuple[Any, _ManualFeeInstructions]:
    """Remove only the priority-fee instructions Fordefi is allowed to manage."""
    account_keys = list(message.account_keys)
    kept: list[CompiledInstruction] = []
    limit: int | None = None
    price: int | None = None

    for instruction in message.instructions:
        program_index = instruction.program_id_index
        data = bytes(instruction.data)
        is_mutable_fee = (
            program_index < len(account_keys)
            and account_keys[program_index] == COMPUTE_BUDGET_ID
            and data
            and data[0] in (_SET_COMPUTE_UNIT_LIMIT, _SET_COMPUTE_UNIT_PRICE)
        )
        if not is_mutable_fee:
            kept.append(instruction)
            continue
        if instruction.accounts:
            raise ValueError("priority-fee instruction has accounts")
        if data[0] == _SET_COMPUTE_UNIT_LIMIT:
            if limit is not None:
                raise ValueError("duplicate SetComputeUnitLimit")
            if len(data) != 5:
                raise ValueError("malformed SetComputeUnitLimit")
            limit = int.from_bytes(data[1:], "little")
            if limit == 0 or limit > _MAX_COMPUTE_UNIT_LIMIT:
                raise ValueError("SetComputeUnitLimit is out of range")
        else:
            if price is not None:
                raise ValueError("duplicate SetComputeUnitPrice")
            if len(data) != 9:
                raise ValueError("malformed SetComputeUnitPrice")
            price = int.from_bytes(data[1:], "little")

    compute_budget_indexes = [
        index for index, account_key in enumerate(account_keys) if account_key == COMPUTE_BUDGET_ID
    ]
    if len(compute_budget_indexes) == 1:
        key_index = compute_budget_indexes[0]
        header = message.header
        first_readonly_unsigned = len(account_keys) - header.num_readonly_unsigned_accounts
        is_readonly_unsigned = (
            header.num_readonly_unsigned_accounts > 0
            and key_index >= header.num_required_signatures
            and key_index >= first_readonly_unsigned
        )
        is_still_used = any(
            instruction.program_id_index == key_index or key_index in instruction.accounts
            for instruction in kept
        )
        if is_readonly_unsigned and not is_still_used:
            del account_keys[key_index]
            header = MessageHeader(
                header.num_required_signatures,
                header.num_readonly_signed_accounts,
                header.num_readonly_unsigned_accounts - 1,
            )
            reindexed: list[CompiledInstruction] = []
            for instruction in kept:
                program_index = instruction.program_id_index
                if program_index > key_index:
                    program_index -= 1
                accounts = bytes(
                    index - 1 if index > key_index else index for index in instruction.accounts
                )
                reindexed.append(
                    CompiledInstruction(program_index, bytes(instruction.data), accounts)
                )
            kept = reindexed
        else:
            header = message.header
    else:
        header = message.header

    if isinstance(message, Message):
        normalized: Any = Message.new_with_compiled_instructions(
            header.num_required_signatures,
            header.num_readonly_signed_accounts,
            header.num_readonly_unsigned_accounts,
            account_keys,
            message.recent_blockhash,
            kept,
        )
    else:
        normalized = MessageV0(
            header,
            account_keys,
            message.recent_blockhash,
            kept,
            message.address_table_lookups,
        )
    return normalized, _ManualFeeInstructions(limit=limit, price=price)


def _effective_priority_fee_lamports(fee: _ManualFeeInstructions) -> int:
    """Convert a compute-unit price into the lamports it can actually cost.

    Rounds up, and charges a message with no explicit limit at the maximum the
    runtime allows.
    """
    price = fee.price or 0
    limit = fee.limit or _MAX_COMPUTE_UNIT_LIMIT
    return (price * limit + _MICRO_LAMPORTS_PER_LAMPORT - 1) // _MICRO_LAMPORTS_PER_LAMPORT


def _messages_match_with_blockhash_policy(
    original: Any, returned: Any, *, replaceable_blockhash: bool
) -> bool:
    if type(original) is not type(returned):
        return False
    if replaceable_blockhash:
        returned = _message_with_recent_blockhash(returned, original.recent_blockhash)
    return signed_message_bytes(original) == signed_message_bytes(returned)


def _timestamp_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class FordefiSignerConfig:
    """Configuration for a Fordefi signer.

    Provide exactly one request-signing mechanism: a PEM-encoded ECDSA P-256
    key in ``private_key_pem``, or a custom ``FordefiRequestSigner`` in
    ``request_signer`` for KMS/HSM-backed request signing.

    ``chain`` (``solana_devnet`` / ``solana_mainnet``) switches from black-box
    raw signing to Fordefi's native Solana API types. ``push_mode`` controls
    whether Fordefi broadcasts native transactions (``auto``) or returns them
    for caller-managed broadcasting (``manual``). Messages use ``solana_message``.

    ``fee`` is the native-mode fee configuration passed through verbatim,
    e.g. ``{"type": "priority", "priority_level": "medium"}`` or
    ``{"type": "custom", "priority_fee": "1000"}``. Requires ``chain``.

    ``max_priority_fee_lamports`` bounds the priority fee Fordefi may introduce
    on its own initiative during native manual signing. ``None`` applies
    ``DEFAULT_MAX_PRIORITY_FEE_LAMPORTS`` unless ``fee`` states a custom
    ``priority_fee``, in which case that bound governs. The ceiling never applies
    to a compute-unit price the caller placed in the transaction themselves,
    because those requests are validated byte-for-byte and carry no Fordefi
    discretion.
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
    push_mode: FordefiPushMode = "auto"
    max_priority_fee_lamports: int | None = None


class FordefiSigner(SolanaSigner):
    """Signer backed by a Fordefi vault.

    ``init()`` must be awaited before use — it fetches the vault from Fordefi
    and verifies that the configured ``public_key`` actually belongs to
    ``vault_id``. ``create_fordefi_signer()`` does this for you.

    Black-box mode (default) signs the caller's exact message bytes and the
    caller broadcasts. Native auto mode lets Fordefi replace the blockhash and
    fees, sign, and broadcast. For the unsigned native manual requests supported
    here, Fordefi may replace the blockhash and manage priority-fee instructions,
    then returns the validated transaction through
    ``SignedTransaction.transaction``; see ``sign_transaction``.
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
        if config.push_mode not in ("auto", "manual"):
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "push_mode must be one of auto, manual",
            )
        if config.push_mode == "manual" and config.chain is None:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "manual push_mode requires chain to be set (native Solana mode)",
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
        self._push_mode = config.push_mode
        self._max_priority_fee_lamports = config.max_priority_fee_lamports
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

    @property
    def broadcasts_transactions(self) -> bool:
        return self._chain is not None and self._push_mode == "auto"

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

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign ``transaction`` via Fordefi MPC.

        Black-box mode signs the exact message bytes, places the signature in
        ``transaction`` in place, and returns the encoded transaction for the
        caller to broadcast.

        Native auto mode submits the message with ``push_mode: auto``. Fordefi
        replaces the blockhash (and optionally fees), signs, and broadcasts the
        transaction itself. The returned ``encoded_transaction`` is empty and
        the caller's transaction is left unmodified; the signature identifies
        the on-chain transaction. The configured vault must be the sole signer.

        Native manual mode submits an unsigned message with ``push_mode:
        manual``. Fordefi may replace the blockhash and manage compute-unit
        price/limit instructions, then signs without broadcasting. All content
        outside that documented mutation set is validated exactly. Because
        solders messages are read-only, the caller's object stays untouched and
        the validated replacement is returned in
        ``SignedTransaction.transaction`` and as canonical base64 in
        ``encoded_transaction``. Fordefi must be the fee payer and sign first.

        Native auto mode is not retry-safe: any failure after Fordefi accepts the
        submission raises ``BROADCAST_UNCONFIRMED`` carrying
        ``provider_transaction_id``; check that transaction with Fordefi
        before retrying. A submission that fails without a usable response
        raises ``BROADCAST_UNCONFIRMED`` with no ``provider_transaction_id``.

        Each native create carries a deterministic ``x-idempotence-id``. Manual
        mode uses a mode/chain/vault namespace so it never collides with auto.
        """
        if self._chain is not None:
            if self._push_mode == "manual":
                return await self._sign_transaction_native_manual(transaction)
            return await self._sign_transaction_native_auto(transaction)
        message_data = signed_message_bytes(transaction.message)
        signature = await self._sign_black_box(message_data)
        self._verify_signature(signature, message_data)
        add_signature_to_transaction(transaction, self._public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

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

    async def _sign_transaction_native_auto(
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
        try:
            return await self._finish_native_broadcast(transaction_id)
        except asyncio.CancelledError as error:
            # Awaiting a cancelled task strips the raised instance, so the id is
            # also logged; the re-raise must stay a CancelledError for asyncio.
            _logger.warning(
                "Fordefi may have executed cancelled transaction %s; check it before retrying",
                transaction_id,
            )
            raise asyncio.CancelledError(
                "Fordefi may have executed the transaction, but the outcome could "
                f"not be confirmed (provider transaction id: {transaction_id})"
            ) from error
        except SignerError as error:
            raise SignerError(
                SignerErrorCode.BROADCAST_UNCONFIRMED,
                error._detail,
                provider_transaction_id=transaction_id,
            ) from None

    @staticmethod
    def _required_signer_keys(transaction: VersionedTransaction) -> tuple[Pubkey, ...]:
        required_signatures = transaction.message.header.num_required_signatures
        account_keys = transaction.message.account_keys
        if len(account_keys) < required_signatures:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Transaction does not contain all required signer account keys",
            )
        return tuple(account_keys[:required_signatures])

    def _validate_native_manual_transaction(self, transaction: VersionedTransaction) -> None:
        required_signers = self._required_signer_keys(transaction)
        if not required_signers or required_signers[0] != self._public_key:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native manual signing requires the configured vault to be "
                "the transaction fee payer",
            )
        default_signature = Signature.default()
        if any(signature != default_signature for signature in transaction.signatures):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi native manual signing must run before any transaction "
                "signatures are applied",
            )

    def _manual_idempotence_id(self, message_data: bytes) -> str:
        namespace = f"fordefi:solana:manual:{self._chain}:{self._vault_id}:".encode() + message_data
        return idempotency_key_from_message(namespace)

    def _validate_manual_custom_fee(self, fee: _ManualFeeInstructions) -> None:
        if not isinstance(self._fee, dict) or self._fee.get("type") != "custom":
            return
        configured_unit_price = self._fee.get("unit_price")
        if configured_unit_price is not None:
            try:
                expected_price = int(configured_unit_price)
            except (TypeError, ValueError):
                raise ValueError("configured custom unit_price is invalid") from None
            if expected_price < 0 or fee.price is None or expected_price != fee.price:
                raise ValueError(
                    "returned compute-unit price does not match the configured custom unit_price"
                )
        configured_priority_fee = self._fee.get("priority_fee")
        if configured_priority_fee is not None and fee.price is not None:
            try:
                maximum_fee = int(configured_priority_fee)
            except (TypeError, ValueError):
                raise ValueError("configured custom priority_fee is invalid") from None
            if maximum_fee < 0:
                raise ValueError("configured custom priority_fee is invalid")
            if _effective_priority_fee_lamports(fee) > maximum_fee:
                raise ValueError("returned priority fee exceeds the configured custom priority_fee")

    def _manual_priority_fee_ceiling(self) -> int | None:
        """Absolute lamport bound for a Fordefi-introduced priority fee.

        Returns ``None`` when the caller already stated their own total bound
        through a custom ``priority_fee``.
        """
        if self._max_priority_fee_lamports is not None:
            return self._max_priority_fee_lamports
        if (
            isinstance(self._fee, dict)
            and self._fee.get("type") == "custom"
            and self._fee.get("priority_fee") is not None
        ):
            return None
        return DEFAULT_MAX_PRIORITY_FEE_LAMPORTS

    def _validate_manual_fee_ceiling(self, fee: _ManualFeeInstructions) -> None:
        """Bound a priority fee Fordefi introduced on its own initiative.

        Keeps a compromised or malfunctioning response from draining the fee
        payer even when no custom fee bound is configured.
        """
        if fee.price is None:
            return
        ceiling = self._manual_priority_fee_ceiling()
        if ceiling is None:
            return
        if _effective_priority_fee_lamports(fee) > ceiling:
            raise ValueError(
                "returned priority fee exceeds the maximum; raise "
                "max_priority_fee_lamports to allow it"
            )

    def _validate_manual_message_mutation(
        self, original: VersionedTransaction, returned: VersionedTransaction
    ) -> None:
        if type(original.message) is not type(returned.message):
            raise ValueError("changed the transaction message version")
        if original.uses_durable_nonce():
            if not _messages_match_with_blockhash_policy(
                original.message, returned.message, replaceable_blockhash=False
            ):
                raise ValueError("changed a durable-nonce transaction")
            if isinstance(original.message, (Message, MessageV0)):
                _, original_fee = _normalize_manual_fee_message(original.message)
                self._validate_manual_custom_fee(original_fee)
            return
        if isinstance(original.message, MessageV1):
            if not _messages_match_with_blockhash_policy(
                original.message, returned.message, replaceable_blockhash=True
            ):
                raise ValueError("changed v1 content outside the recent blockhash")
            return

        if not isinstance(original.message, (Message, MessageV0)) or not isinstance(
            returned.message, (Message, MessageV0)
        ):
            raise ValueError("unsupported transaction message version")

        normalized_original, original_fee = _normalize_manual_fee_message(original.message)
        if original_fee.price is not None:
            if not _messages_match_with_blockhash_policy(
                original.message, returned.message, replaceable_blockhash=True
            ):
                raise ValueError(
                    "changed transaction content after the caller set a compute-unit price"
                )
            self._validate_manual_custom_fee(original_fee)
            return

        normalized_returned, returned_fee = _normalize_manual_fee_message(returned.message)
        # The caller set no compute-unit price, so any price here is Fordefi's own
        # and is bounded by the absolute ceiling as well as any custom fee config.
        self._validate_manual_fee_ceiling(returned_fee)
        self._validate_manual_custom_fee(returned_fee)
        if not _messages_match_with_blockhash_policy(
            normalized_original, normalized_returned, replaceable_blockhash=True
        ):
            raise ValueError(
                "changed transaction content outside the recent blockhash and priority fee"
            )

    async def _sign_transaction_native_manual(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        self._validate_native_manual_transaction(transaction)
        message_data = signed_message_bytes(transaction.message)
        transaction_id = await self._post_transaction(
            self._solana_transaction_request(message_data),
            idempotence_id=self._manual_idempotence_id(message_data),
        )
        return await self._finish_native_manual(transaction_id, transaction)

    async def _finish_native_manual(
        self, transaction_id: str, original: VersionedTransaction
    ) -> SignedTransaction:
        result = await self._poll_for_result(transaction_id, pushable=False)
        raw_transaction = result.get("raw_transaction")
        if not isinstance(raw_transaction, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual solana_transaction response missing raw_transaction",
            )
        try:
            wire_bytes = base64.b64decode(raw_transaction, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode Fordefi manual raw_transaction base64",
            ) from None
        if len(wire_bytes) > SOLANA_PACKET_DATA_SIZE:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual wire transaction exceeds the Solana size limit",
            )
        try:
            returned = VersionedTransaction.from_bytes(wire_bytes)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to deserialize Fordefi manual wire transaction",
            ) from None

        original_signers = self._required_signer_keys(original)
        returned_signers = self._required_signer_keys(returned)
        if returned_signers != original_signers:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual signing changed the transaction required-signer set",
            )

        try:
            self._validate_manual_message_mutation(original, returned)
        except ValueError as error:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Fordefi manual signing returned an unauthorized transaction mutation: {error}",
            ) from None
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to validate Fordefi-returned manual transaction message",
            ) from None

        signatures = list(returned.signatures)
        if len(signatures) != len(returned_signers):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual wire transaction has an invalid signature-slot count",
            )
        signature = signatures[0]
        default_signature = Signature.default()
        if signature == default_signature:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual wire transaction did not contain the configured vault signature",
            )
        if any(item != default_signature for item in signatures[1:]):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual signing unexpectedly populated a downstream signer slot",
            )
        self._verify_signature(signature, signed_message_bytes(returned.message))

        try:
            canonical_wire = bytes(returned)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to serialize Fordefi manual wire transaction",
            ) from None
        if len(canonical_wire) > SOLANA_PACKET_DATA_SIZE:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Fordefi manual wire transaction exceeds the Solana size limit",
            )

        return SignedTransaction(
            encoded_transaction=base64.b64encode(canonical_wire).decode("ascii"),
            signature=signature,
            is_complete=has_all_required_signatures(returned),
            transaction=returned,
        )

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
        self._verify_signature(signature, signed_message_bytes(returned.message))
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
