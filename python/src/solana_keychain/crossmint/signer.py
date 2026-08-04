"""Crossmint Wallets API signer integration."""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import base58
import httpx
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction, VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import assert_https_url, fetch_signer_json, normalize_base_url
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
)
from solana_keychain.crossmint.derive import derive_signing_key

DEFAULT_API_BASE_URL = "https://www.crossmint.com/api"
API_VERSION_PATH = "2025-06-09"
DEFAULT_POLL_INTERVAL_MS = 1000
DEFAULT_MAX_POLL_ATTEMPTS = 60
AVAILABILITY_TIMEOUT_SECONDS = 5.0

ED25519_SIGNATURE_LENGTH = 64

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

    ``init()`` must be awaited before signing — it resolves the wallet address.
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
    ) -> dict[str, Any]:
        headers = {"X-API-KEY": self._api_key}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
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
        if self._public_key is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "CrossmintSigner is not initialized; call init() before signing",
            )
        return self._public_key

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    async def _create_transaction(self, transaction_b58: str) -> dict[str, Any]:
        params: dict[str, Any] = {"transaction": transaction_b58}
        if self._signer is not None:
            params["signer"] = self._signer
        return await self._request_with_required_field(
            method="POST",
            url=self._wallets_url("transactions"),
            required_field="id",
            context="create_transaction",
            json_body={"params": params},
        )

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

    async def _poll_transaction(self, response: dict[str, Any]) -> dict[str, Any]:
        approval_submitted = False
        for _ in range(self._max_poll_attempts):
            status = response.get("status")
            if status == "success":
                return response
            if status == "failed":
                raise SignerError(
                    SignerErrorCode.SIGNING_FAILED,
                    f"Crossmint transaction failed: {self._failure_detail(response)}",
                )
            if status == "awaiting-approval" and not approval_submitted:
                # Approve at most once; the approval may register asynchronously,
                # so afterwards awaiting-approval re-polls like any other
                # in-flight status.
                response = await self._handle_awaiting_approval(response)
                approval_submitted = True
                continue
            await asyncio.sleep(self._poll_interval_ms / 1000)
            response = await self._get_transaction(str(response.get("id")))

        status = response.get("status")
        if status == "success":
            return response
        if status == "failed":
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Crossmint transaction failed: {self._failure_detail(response)}",
            )
        if status == "awaiting-approval" and not approval_submitted:
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

    def _verify_signature_matches_message(self, signature: Signature, message: bytes) -> None:
        if not signature.verify(self._initialized_pubkey(), message):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint returned a signature for different bytes",
            )

    def _extract_signature_from_serialized_transaction(
        self, serialized_transaction: str, expected_message: bytes
    ) -> Signature:
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
        num_required = message.header.num_required_signatures
        account_keys = list(message.account_keys)
        if len(account_keys) < num_required:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Invalid account index: not enough account keys"
            )
        public_key = self._initialized_pubkey()
        try:
            position = account_keys[:num_required].index(public_key)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Failed to locate signer pubkey in Crossmint transaction",
            ) from None

        signatures = list(transaction.signatures)
        if position >= len(signatures) or signatures[position] == Signature.default():
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Crossmint onChain.transaction did not contain a signer signature",
            )
        signature = signatures[position]
        # Verify against the caller's message bytes, not the returned ones: if the
        # service rewrote the transaction (blockhash, wrapping), its signature does
        # not sign the caller's transaction and must not be attached to it.
        self._verify_signature_matches_message(signature, expected_message)
        return signature

    def _extract_signature_from_response(
        self, response: dict[str, Any], expected_message: bytes
    ) -> Signature:
        on_chain = response.get("onChain")
        if isinstance(on_chain, dict):
            serialized_transaction = on_chain.get("transaction")
            if isinstance(serialized_transaction, str):
                try:
                    return self._extract_signature_from_serialized_transaction(
                        serialized_transaction, expected_message
                    )
                except SignerError:
                    pass

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
                self._verify_signature_matches_message(signature, expected_message)
                return signature

        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Unable to extract signature from Crossmint transaction response",
        )

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        public_key = self._initialized_pubkey()
        expected_message = transaction.message_data()
        transaction_b58 = base58.b58encode(bytes(transaction)).decode("ascii")

        create_response = await self._create_transaction(transaction_b58)
        final_response = await self._poll_transaction(create_response)
        signature = self._extract_signature_from_response(final_response, expected_message)

        add_signature_to_transaction(transaction, public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Crossmint sign_message is not supported for Solana wallets in this signer",
        )

    async def is_available(self) -> bool:
        try:
            await asyncio.wait_for(self._fetch_wallet(), AVAILABILITY_TIMEOUT_SECONDS)
        except (SignerError, asyncio.TimeoutError):
            return False
        return True


async def create_crossmint_signer(config: CrossmintSignerConfig) -> CrossmintSigner:
    """Create a ready-to-use Crossmint signer (awaits ``init()``)."""
    signer = CrossmintSigner(config)
    await signer.init()
    return signer
