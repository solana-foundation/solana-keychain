"""Crossmint Wallets API signer integration."""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import base58
import httpx
from solders.keypair import Keypair
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import (
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
    probe_availability,
    provider_may_have_accepted,
)
from solana_keychain.core.signer import (
    SignedTransaction,
    SolanaSigner,
    require_initialized,
)
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    idempotency_key_from_message,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.crossmint.derive import derive_signing_key

_logger = logging.getLogger("solana_keychain")

DEFAULT_API_BASE_URL = "https://www.crossmint.com/api"
API_VERSION_PATH = "2025-06-09"
DEFAULT_POLL_INTERVAL_MS = 1000
DEFAULT_MAX_POLL_ATTEMPTS = 60


_AWAITING_APPROVAL_ERROR = (
    "Crossmint transaction is awaiting approval; additional signer approvals are required"
)

_ENCODE_URI_COMPONENT_SAFE = "-_.!~*'()"


def _encode_uri_component(value: str) -> str:
    return quote(value, safe=_ENCODE_URI_COMPONENT_SAFE)


@dataclass
class CrossmintSignerConfig:
    """Configuration for a Crossmint signer.

    ``signer_secret`` is an optional server delegated-signer secret
    (``xmsk1_<64hex>``); when provided, an Ed25519 keypair is derived from it and
    ``awaiting-approval`` transactions are approved automatically. ``signer``
    overrides the delegated-signer locator (default ``server:<derived pubkey>``).

    Trust boundary for ``signer_secret``: the approval challenge is the message of
    the transaction Crossmint will execute, which is not derivable from the one
    submitted because Crossmint rewrites it to sponsor gas. Setting it delegates to
    Crossmint the choice of what gets approved. The signer confirms after the fact
    that its approval covers the transaction that executed, not that the transaction
    matches the caller's intent.
    """

    api_key: str = field(repr=False)
    wallet_locator: str
    signer_secret: str | None = field(default=None, repr=False)
    signer: str | None = None
    api_base_url: str = DEFAULT_API_BASE_URL
    poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS
    max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class CrossmintSigner(SolanaSigner):
    """Signer backed by a Crossmint smart or MPC wallet.

    Crossmint is a broadcast-managed signer: it rewrites the transaction (gas
    sponsorship, priority fee, its own blockhash) and broadcasts server-side, so
    returned signatures cover Crossmint's bytes rather than the caller's.

    ``init()`` must be awaited before signing; it resolves the wallet address.
    ``create_crossmint_signer()`` does this for you. ``sign_message`` is
    intentionally unsupported: the Wallets API signs transactions only.
    """

    def __init__(self, config: CrossmintSignerConfig) -> None:
        if not config.api_key:
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "api_key must not be empty")
        if not config.wallet_locator:
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "wallet_locator must not be empty")
        if config.poll_interval_ms <= 0:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "poll_interval_ms must be greater than 0"
            )
        if config.max_poll_attempts <= 0:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "max_poll_attempts must be greater than 0"
            )
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._api_key = config.api_key
        self._wallet_locator = config.wallet_locator
        self._poll_interval_ms = config.poll_interval_ms
        self._max_poll_attempts = config.max_poll_attempts
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

        self._signing_key: Keypair | None = None
        self._signer: str | None = config.signer
        if config.signer_secret is not None:
            self._signing_key = derive_signing_key(config.signer_secret, config.api_key)
            self._signer = config.signer or f"server:{self._signing_key.pubkey()}"
        self._delegated_pubkeys = self._resolve_delegated_pubkeys()

    def _resolve_delegated_pubkeys(self) -> list[Pubkey]:
        """Every delegated-signer key the configuration makes known.

        A smart wallet signs through its delegated signer, not the wallet address.
        Both sources are collected because a ``signer`` locator may name a different
        key than ``signer_secret`` derives, and either can be the one that signs.
        """
        candidates: list[Pubkey] = []
        if self._signing_key is not None:
            candidates.append(self._signing_key.pubkey())
        if self._signer is not None and self._signer.startswith("server:"):
            try:
                candidates.append(Pubkey.from_string(self._signer.removeprefix("server:").strip()))
            except Exception:
                pass
        return candidates

    def __repr__(self) -> str:
        return f"CrossmintSigner(pubkey={self._public_key}, wallet_locator={self._wallet_locator})"

    def _wallets_url(self, *segments: str) -> str:
        url = (
            f"{self._api_base_url}/{API_VERSION_PATH}/wallets/"
            f"{_encode_uri_component(self._wallet_locator)}"
        )
        for segment in segments:
            url += f"/{_encode_uri_component(segment)}"
        return url

    @staticmethod
    def _extract_error_message(value: Any) -> str | None:
        if not isinstance(value, dict):
            return None
        message = value.get("message")
        if isinstance(message, str):
            return message
        error = value.get("error")
        if isinstance(error, str):
            return error
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            return str(error["message"])
        return None

    async def _request_with_required_field(
        self,
        *,
        method: str,
        url: str,
        required_field: str,
        context: str,
        json_body: Any | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = {"X-API-KEY": self._api_key}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        response = await fetch_signer_json(
            url=url,
            provider_name="Crossmint",
            method=method,
            headers=headers,
            json_body=json_body,
            client=self._http_client,
        )
        if not isinstance(response, dict) or response.get(required_field) is None:
            message = self._extract_error_message(response)
            if message is not None:
                raise SignerError(SignerErrorCode.REMOTE_API_ERROR, f"{context}: {message}")
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                f"{context}: missing expected field '{required_field}' in response",
            )
        return response

    async def _fetch_wallet(self) -> dict[str, Any]:
        return await self._request_with_required_field(
            method="GET",
            url=self._wallets_url(),
            required_field="address",
            context="fetch_wallet",
        )

    async def init(self) -> None:
        """Resolve the wallet address. Must be awaited before signing."""
        wallet = await self._fetch_wallet()
        chain_type = str(wallet.get("chainType", ""))
        if chain_type.lower() != "solana":
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, f"Expected Solana wallet, got chainType={chain_type}"
            )
        wallet_type = str(wallet.get("type", ""))
        if wallet_type.lower() not in ("smart", "mpc"):
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, f"Unsupported Crossmint wallet type: {wallet_type}"
            )
        try:
            self._public_key = Pubkey.from_string(str(wallet.get("address", "")))
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                "Invalid Solana public key returned by Crossmint wallet",
            ) from None

    def _initialized_pubkey(self) -> Pubkey:
        return require_initialized(self._public_key, "CrossmintSigner")

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    @property
    def broadcasts_transactions(self) -> bool:
        return True

    async def _create_transaction(
        self, transaction_b58: str, idempotency_key: str
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"transaction": transaction_b58}
        if self._signer is not None:
            params["signer"] = self._signer
        try:
            return await self._request_with_required_field(
                method="POST",
                url=self._wallets_url("transactions"),
                required_field="id",
                context="create_transaction",
                json_body={"params": params},
                extra_headers={"x-idempotency-key": idempotency_key},
            )
        except asyncio.CancelledError as error:
            # The re-raise must stay a CancelledError for asyncio, so the warning
            # goes to the log.
            _logger.warning(
                "Crossmint may have created a cancelled transaction with no id "
                "returned; check before retrying"
            )
            raise asyncio.CancelledError(
                "Crossmint may have created the transaction, but no transaction id was returned"
            ) from error
        except SignerError as error:
            if not provider_may_have_accepted(error.status_code):
                raise
            # Crossmint may be executing a transaction whose id never reached us.
            raise SignerError(
                SignerErrorCode.BROADCAST_UNCONFIRMED,
                error._detail,
                status_code=error.status_code,
            ) from None

    async def _get_transaction(self, transaction_id: str) -> dict[str, Any]:
        return await self._request_with_required_field(
            method="GET",
            url=self._wallets_url("transactions", transaction_id),
            required_field="id",
            context="get_transaction",
        )

    @staticmethod
    def _failure_detail(response: dict[str, Any]) -> str:
        error = response.get("error")
        return json.dumps(error) if error is not None else "unknown error"

    def _settled_or_none(self, response: dict[str, Any]) -> dict[str, Any] | None:
        status = response.get("status")
        if status == "success":
            return response
        if status == "failed":
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Crossmint transaction failed: {self._failure_detail(response)}",
            )
        return None

    async def _poll_transaction(self, response: dict[str, Any]) -> dict[str, Any]:
        approval_submitted = False
        for _ in range(self._max_poll_attempts):
            settled = self._settled_or_none(response)
            if settled is not None:
                return settled
            if response.get("status") == "awaiting-approval" and not approval_submitted:
                # Approve at most once; the approval may register asynchronously,
                # so afterwards awaiting-approval re-polls like any other
                # in-flight status.
                response = await self._handle_awaiting_approval(response)
                approval_submitted = True
                continue
            await asyncio.sleep(self._poll_interval_ms / 1000)
            response = await self._get_transaction(str(response.get("id")))

        settled = self._settled_or_none(response)
        if settled is not None:
            return settled
        if response.get("status") == "awaiting-approval" and not approval_submitted:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, _AWAITING_APPROVAL_ERROR)
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"Crossmint transaction polling timed out after {self._max_poll_attempts} attempts",
        )

    async def _handle_awaiting_approval(self, response: dict[str, Any]) -> dict[str, Any]:
        if self._signing_key is None or self._signer is None:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, _AWAITING_APPROVAL_ERROR)

        # A multi-approver wallet may list challenges for other approvers; signing
        # one of those with our key yields a vendor 4xx, so only the entry matching
        # our signer locator is ours to approve.
        approvals = response.get("approvals")
        pending_entries = approvals.get("pending", []) if isinstance(approvals, dict) else []
        our_entry = next(
            (
                entry
                for entry in pending_entries
                if isinstance(entry, dict)
                and isinstance(entry.get("signer"), dict)
                and entry["signer"].get("locator") == self._signer
            ),
            None,
        )
        if our_entry is None:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, _AWAITING_APPROVAL_ERROR)

        message = our_entry.get("message")
        if not isinstance(message, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint transaction awaiting approval but no pending message found",
            )

        try:
            message_bytes = base58.b58decode(message)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Failed to decode approval message as base58",
            ) from None
        signature = self._signing_key.sign_message(message_bytes)

        return await self._request_with_required_field(
            method="POST",
            url=self._wallets_url("transactions", str(response.get("id")), "approvals"),
            required_field="id",
            context="submit_approval",
            json_body={"approvals": [{"signer": self._signer, "signature": str(signature)}]},
        )

    def _verification_candidates(self) -> list[Pubkey]:
        """Keys that may have signed: the wallet address for ``mpc``, the delegated
        signer for ``smart``. The response does not say which, so try both."""
        candidates = [self._initialized_pubkey()]
        for delegated in self._delegated_pubkeys:
            if delegated not in candidates:
                candidates.append(delegated)
        return candidates

    def _extract_signature_from_serialized_transaction(
        self, serialized_transaction: str
    ) -> tuple[Signature, VersionedTransaction]:
        try:
            transaction_bytes = base58.b58decode(serialized_transaction)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode Crossmint onChain.transaction as base58",
            ) from None
        try:
            transaction = VersionedTransaction.from_bytes(transaction_bytes)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to deserialize Crossmint onChain.transaction",
            ) from None

        message = transaction.message
        if not isinstance(message, (Message, MessageV0)):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint returned a transaction with an unsupported message version",
            )
        num_required = message.header.num_required_signatures
        account_keys = list(message.account_keys)
        if len(account_keys) < num_required:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Invalid account index: not enough account keys"
            )
        # Require a verifying signature, not just presence in a slot: the wallet
        # address can occupy a slot it never signed.
        signer_slots = account_keys[:num_required]
        signed_bytes = signed_message_bytes(message)
        signatures = list(transaction.signatures)
        for candidate in self._verification_candidates():
            if candidate not in signer_slots:
                continue
            position = signer_slots.index(candidate)
            if position >= len(signatures) or signatures[position] == Signature.default():
                continue
            if signatures[position].verify(candidate, signed_bytes):
                return signatures[position], transaction
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "No configured signer holds a verifying signature in the Crossmint transaction",
        )

    @staticmethod
    def _executed_message_bytes(transaction: VersionedTransaction) -> bytes:
        message = transaction.message
        if not isinstance(message, (Message, MessageV0)):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint returned a transaction with an unsupported message version",
            )
        return signed_message_bytes(message)

    def _extract_signature_from_approvals(
        self, response: dict[str, Any], serialized_transaction: str
    ) -> tuple[Signature, VersionedTransaction] | None:
        """This wallet's signature over the transaction Crossmint executed.

        For a rewritten transaction it arrives in ``approvals.submitted`` covering the
        rewritten message, not in a signature slot. Verified locally regardless.
        """
        approvals = response.get("approvals")
        submitted = approvals.get("submitted") if isinstance(approvals, dict) else None
        if not isinstance(submitted, list) or not submitted:
            return None
        try:
            transaction = VersionedTransaction.from_bytes(base58.b58decode(serialized_transaction))
        except Exception:
            return None
        try:
            executed_message = self._executed_message_bytes(transaction)
        except SignerError:
            return None
        candidates = self._verification_candidates()
        for entry in submitted:
            if not isinstance(entry, dict):
                continue
            signer = entry.get("signer")
            address = signer.get("address") if isinstance(signer, dict) else None
            encoded = entry.get("signature")
            if not isinstance(address, str) or not isinstance(encoded, str):
                continue
            try:
                approver = Pubkey.from_string(address)
                signature = Signature.from_bytes(base58.b58decode(encoded))
            except Exception:
                continue
            if approver in candidates and signature.verify(approver, executed_message):
                return signature, transaction
        return None

    @staticmethod
    def _broadcast_transaction_id(transaction: VersionedTransaction) -> Signature:
        """The landed transaction's fee-payer (slot 0) signature, the value RPC
        transaction lookups accept."""
        account_keys = list(transaction.message.account_keys)
        signatures = list(transaction.signatures)
        if not account_keys:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint transaction has no fee payer to identify it by",
            )
        if not signatures or signatures[0] == Signature.default():
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint transaction carries no fee-payer signature to identify it by",
            )
        if not signatures[0].verify(
            account_keys[0], CrossmintSigner._executed_message_bytes(transaction)
        ):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint fee-payer signature does not verify over the executed transaction",
            )
        return signatures[0]

    def _extract_signature_from_response(
        self, response: dict[str, Any], expected_message: bytes
    ) -> tuple[Signature, VersionedTransaction | None]:
        """The signing result, plus the broadcast transaction when Crossmint rewrote one.

        A non-``None`` transaction means Crossmint changed the message before
        signing and broadcast the result server-side; the signature is then the
        landed transaction's fee-payer identifier.
        """
        on_chain = response.get("onChain")
        if isinstance(on_chain, dict):
            embedded_error: SignerError | None = None
            serialized_transaction = on_chain.get("transaction")
            if isinstance(serialized_transaction, str):
                try:
                    signature, returned = self._extract_signature_from_serialized_transaction(
                        serialized_transaction
                    )
                except SignerError as transaction_error:
                    # A rewritten transaction's approval lives in approvals.submitted.
                    approved = self._extract_signature_from_approvals(
                        response, serialized_transaction
                    )
                    if approved is not None:
                        _, returned = approved
                        return self._broadcast_transaction_id(returned), returned
                    # The txId path can only succeed when Crossmint signed the caller's
                    # exact bytes, so for a rewritten transaction it is not a real
                    # fallback. Keep the embedded-transaction error as the reported
                    # cause: it says which check failed, where txId says only that a
                    # signature did not cover the caller's message.
                    if not isinstance(on_chain.get("txId"), str):
                        raise
                    embedded_error = transaction_error
                else:
                    if self._executed_message_bytes(returned) == expected_message:
                        return signature, None
                    return self._broadcast_transaction_id(returned), returned

            tx_id = on_chain.get("txId")
            if isinstance(tx_id, str):
                try:
                    signature_bytes = base58.b58decode(tx_id)
                    if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
                        raise ValueError
                    signature = Signature.from_bytes(signature_bytes)
                except Exception:
                    raise SignerError(
                        SignerErrorCode.SIGNING_FAILED,
                        "Crossmint onChain.txId was not a valid Solana signature",
                    ) from None
                # A txId counts only if it covers the caller's bytes, and any
                # configured signer may have produced it.
                if not any(
                    signature.verify(candidate, expected_message)
                    for candidate in self._verification_candidates()
                ):
                    raise embedded_error or SignerError(
                        SignerErrorCode.SIGNING_FAILED,
                        "Crossmint returned a signature for different bytes",
                    )
                return signature, None

        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Unable to extract signature from Crossmint transaction response",
        )

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign ``transaction`` through Crossmint's managed wallet flow.

        Crossmint may rewrite the transaction (it sponsors gas, so it becomes the
        fee payer) and broadcast it itself. When it does, ``transaction`` is left
        unmodified and ``encoded_transaction`` is empty: the returned signature is
        the landed transaction's fee-payer signature, usable with RPC transaction
        lookups, and it does not cover the caller's message. Only when Crossmint
        signs the caller's exact bytes is the signature placed in ``transaction``.

        Not retry-safe: any failure after the create is accepted raises
        ``BROADCAST_UNCONFIRMED`` carrying ``provider_transaction_id``; check
        that transaction with Crossmint before retrying. A create that fails
        without a usable response raises ``BROADCAST_UNCONFIRMED`` with no
        ``provider_transaction_id``.

        Each create carries an ``x-idempotency-key`` derived from the message
        bytes, so replaying these exact bytes cannot create a second
        transaction; a rebuilt transaction derives a different key and executes
        as a new transfer.
        """
        return await self._execute_managed_transaction(transaction)

    async def _execute_managed_transaction(
        self, transaction: VersionedTransaction
    ) -> SignedTransaction:
        public_key = self._initialized_pubkey()
        expected_message = signed_message_bytes(transaction.message)
        transaction_b58 = base58.b58encode(bytes(transaction)).decode("ascii")

        create_response = await self._create_transaction(
            transaction_b58, idempotency_key_from_message(expected_message)
        )
        provider_transaction_id = str(create_response["id"])
        # Post-create failures leave an outcome Crossmint may still execute, so
        # they surface as BROADCAST_UNCONFIRMED with the transaction id.
        try:
            return await self._finish_managed_transaction(
                create_response, transaction, expected_message, public_key
            )
        except asyncio.CancelledError as error:
            # Awaiting a cancelled task strips the raised instance, so the id is
            # also logged; the re-raise must stay a CancelledError for asyncio.
            _logger.warning(
                "Crossmint may have executed cancelled transaction %s; check it before retrying",
                provider_transaction_id,
            )
            raise asyncio.CancelledError(
                "Crossmint may have executed the transaction, but the outcome could "
                f"not be confirmed (provider transaction id: {provider_transaction_id})"
            ) from error
        except SignerError as error:
            raise SignerError(
                SignerErrorCode.BROADCAST_UNCONFIRMED,
                error._detail,
                provider_transaction_id=provider_transaction_id,
            ) from None

    async def _finish_managed_transaction(
        self,
        create_response: dict[str, Any],
        transaction: VersionedTransaction,
        expected_message: bytes,
        public_key: Pubkey,
    ) -> SignedTransaction:
        final_response = await self._poll_transaction(create_response)
        signature, broadcast_transaction = self._extract_signature_from_response(
            final_response, expected_message
        )

        if broadcast_transaction is not None:
            # Crossmint has already landed this transaction, so the operation is
            # finished whether or not the copy it returns shows every signature
            # slot filled, and there is nothing left for the caller to send.
            return SignedTransaction(encoded_transaction="", signature=signature, is_complete=True)

        add_signature_to_transaction(transaction, public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_and_send_transaction(self, transaction: VersionedTransaction) -> Signature:
        """Sign ``transaction`` and let Crossmint execute it."""
        signed = await self._execute_managed_transaction(transaction)
        return signed.signature

    async def sign_message(self, message: bytes) -> Signature:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Crossmint sign_message is not supported for Solana wallets in this signer",
        )

    async def is_available(self) -> bool:
        async def probe() -> bool:
            await self._fetch_wallet()
            return True

        return await probe_availability(probe)


async def create_crossmint_signer(config: CrossmintSignerConfig) -> CrossmintSigner:
    """Create a ready-to-use Crossmint signer (awaits ``init()``)."""
    signer = CrossmintSigner(config)
    await signer.init()
    return signer
