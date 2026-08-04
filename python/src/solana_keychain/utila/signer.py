"""Utila API signer integration."""

import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

try:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.utila requires the utila extra: pip install 'solana-keychain[utila]'"
    ) from error

import httpx
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

DEFAULT_API_BASE_URL = "https://api.utila.io"
API_AUDIENCE = "https://api.utila.io/"
TOKEN_TTL_SECONDS = 55 * 60
DEFAULT_POLL_INTERVAL_MS = 1000
DEFAULT_MAX_POLL_ATTEMPTS = 60
AVAILABILITY_TIMEOUT_SECONDS = 5.0

_TERMINAL_FAILURE_STATES = frozenset(
    {
        "DECLINED_BY_AML_POLICY",
        "MINED_FAILED",
        "FAILED",
        "DECLINED",
        "REPLACED",
        "CANCELED",
        "DROPPED",
        "EXPIRED",
    }
)

_ENCODE_URI_COMPONENT_SAFE = "-_.!~*'()"


def _encode_uri_component(value: str) -> str:
    return quote(value, safe=_ENCODE_URI_COMPONENT_SAFE)


def _trim_vault_id(value: str) -> str:
    return value.removeprefix("vaults/")


def _trim_wallet_id(value: str) -> str:
    _, separator, wallet_id = value.rpartition("/wallets/")
    return wallet_id if separator else value


@dataclass
class UtilaSignerConfig:
    """Configuration for a Utila signer.

    ``service_account_private_key_pem`` is the service account's RSA key
    (literal ``\\n`` escapes tolerated). ``network`` is a Utila network resource
    name, e.g. ``networks/solana-devnet``. ``designated_signers`` defaults to
    ``["users/{service_account_email}"]``.
    """

    service_account_email: str
    service_account_private_key_pem: str = field(repr=False)
    vault_id: str
    wallet_id: str
    network: str
    api_base_url: str = DEFAULT_API_BASE_URL
    poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS
    max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS
    designated_signers: list[str] | None = None
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class UtilaSigner(SolanaSigner):
    """Signer backed by a Utila MPC vault wallet.

    ``init()`` must be awaited before signing — it resolves the wallet's Solana
    address. ``create_utila_signer()`` does this for you. ``sign_message`` is
    intentionally unsupported: the API signs transactions only.
    """

    def __init__(self, config: UtilaSignerConfig) -> None:
        for name, value in (
            ("service_account_email", config.service_account_email),
            ("service_account_private_key_pem", config.service_account_private_key_pem),
            ("vault_id", config.vault_id),
            ("wallet_id", config.wallet_id),
            ("network", config.network),
        ):
            if not value.strip():
                raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{name} must not be empty")
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

        pem = config.service_account_private_key_pem.replace("\\n", "\n").replace("\r", "")
        try:
            signing_key = load_pem_private_key(pem.strip().encode(), password=None)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY,
                "Failed to parse Utila service account RSA private key",
            ) from None
        if not isinstance(signing_key, rsa.RSAPrivateKey):
            raise SignerError(
                SignerErrorCode.INVALID_PRIVATE_KEY,
                "Failed to parse Utila service account RSA private key",
            )

        self._api_base_url = api_base_url
        self._service_account_email = config.service_account_email
        self._signing_key = signing_key
        self._vault_id = _trim_vault_id(config.vault_id)
        self._wallet_id = _trim_wallet_id(config.wallet_id)
        self._network = config.network
        self._poll_interval_ms = config.poll_interval_ms
        self._max_poll_attempts = config.max_poll_attempts
        self._designated_signers = (
            config.designated_signers
            if config.designated_signers is not None
            else [f"users/{config.service_account_email}"]
        )
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return (
            f"UtilaSigner(pubkey={self._public_key}, vault_id={self._vault_id}, "
            f"wallet_id={self._wallet_id}, network={self._network})"
        )

    def _create_access_token(self) -> str:
        claims = {
            "sub": self._service_account_email,
            "aud": API_AUDIENCE,
            "exp": int(time.time()) + TOKEN_TTL_SECONDS,
        }
        try:
            return pyjwt.encode(claims, self._signing_key, algorithm="RS256")
        except Exception:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Failed to create Utila access token"
            ) from None

    async def _request(self, *, method: str, path: str, json_body: Any | None = None) -> Any:
        return await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Utila",
            method=method,
            headers={"Authorization": f"Bearer {self._create_access_token()}"},
            json_body=json_body,
            client=self._http_client,
        )

    async def _fetch_wallet(self) -> dict[str, Any]:
        path = (
            f"/v2/vaults/{_encode_uri_component(self._vault_id)}"
            f"/wallets/{_encode_uri_component(self._wallet_id)}"
        )
        response = await self._request(method="GET", path=path)
        wallet = response.get("wallet") if isinstance(response, dict) else None
        if not isinstance(wallet, dict):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse Utila fetch_wallet response"
            )
        return wallet

    async def init(self) -> None:
        """Resolve the wallet's Solana address. Must be awaited before signing."""
        wallet = await self._fetch_wallet()
        solana_details = wallet.get("solanaDetails")
        address = solana_details.get("address") if isinstance(solana_details, dict) else None
        if not isinstance(address, str):
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                "Utila wallet response did not include solanaDetails",
            )
        try:
            self._public_key = Pubkey.from_string(address)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                "Invalid Solana address returned by Utila wallet",
            ) from None

    def _initialized_pubkey(self) -> Pubkey:
        if self._public_key is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "UtilaSigner is not initialized; call init() before signing",
            )
        return self._public_key

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    @staticmethod
    def _transaction_envelope(response: Any, context: str) -> dict[str, Any]:
        transaction = response.get("transaction") if isinstance(response, dict) else None
        if not isinstance(transaction, dict):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, f"Failed to parse Utila {context} response"
            )
        return transaction

    async def _initiate_transaction(self, raw_transaction: str) -> dict[str, Any]:
        path = f"/v2/vaults/{_encode_uri_component(self._vault_id)}/transactions:initiate"
        request: dict[str, Any] = {
            "details": {
                "solanaSerializedTransaction": {
                    "network": self._network,
                    "rawTransaction": raw_transaction,
                    "publish": False,
                    "replaceBlockhash": False,
                    "tryReplaceBlockhash": False,
                }
            }
        }
        if self._designated_signers:
            request["designatedSigners"] = self._designated_signers
        response = await self._request(method="POST", path=path, json_body=request)
        return self._transaction_envelope(response, "initiate_transaction")

    async def _get_transaction(self, transaction_id: str) -> dict[str, Any]:
        path = (
            f"/v2/vaults/{_encode_uri_component(self._vault_id)}"
            f"/transactions/{_encode_uri_component(transaction_id)}?view=FULL"
        )
        response = await self._request(method="GET", path=path)
        return self._transaction_envelope(response, "get_transaction")

    @staticmethod
    def _extract_transaction_id(name: str) -> str:
        transaction_id = name.rsplit("/", 1)[-1]
        if not transaction_id:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Utila transaction response missing transaction id",
            )
        return transaction_id

    async def _poll_signed_transaction(self, transaction: dict[str, Any]) -> dict[str, Any]:
        for _ in range(self._max_poll_attempts):
            state = transaction.get("state")
            if state == "SIGNED":
                return transaction
            if state in _TERMINAL_FAILURE_STATES:
                raise SignerError(
                    SignerErrorCode.SIGNING_FAILED,
                    f"Utila transaction reached terminal state {state}",
                )
            await asyncio.sleep(self._poll_interval_ms / 1000)
            transaction_id = self._extract_transaction_id(str(transaction.get("name", "")))
            transaction = await self._get_transaction(transaction_id)

        state = transaction.get("state")
        if state == "SIGNED":
            return transaction
        if state in _TERMINAL_FAILURE_STATES:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Utila transaction reached terminal state {state}",
            )
        raise SignerError(
            SignerErrorCode.REMOTE_API_ERROR,
            f"Utila transaction polling timed out after {self._max_poll_attempts} attempts",
        )

    def _extract_signature_from_raw_transaction(
        self, raw_transaction: str, expected_message: bytes
    ) -> Signature:
        public_key = self._initialized_pubkey()
        try:
            transaction_bytes = base64.b64decode(raw_transaction, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode Utila rawTransaction as base64",
            ) from None
        try:
            transaction = VersionedTransaction.from_bytes(transaction_bytes)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to deserialize Utila rawTransaction",
            ) from None

        message = transaction.message
        if bytes(message) != expected_message:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Utila returned a signed transaction with different message bytes",
            )

        num_required = message.header.num_required_signatures
        account_keys = list(message.account_keys)
        if len(account_keys) < num_required:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Invalid account index: not enough account keys"
            )
        try:
            position = account_keys[:num_required].index(public_key)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Failed to locate signer pubkey in Utila transaction",
            ) from None

        signatures = list(transaction.signatures)
        if position >= len(signatures) or signatures[position] == Signature.default():
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Utila rawTransaction did not contain a signer signature",
            )
        signature = signatures[position]
        if not signature.verify(public_key, expected_message):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Signature verification failed for Utila rawTransaction",
            )
        return signature

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        public_key = self._initialized_pubkey()
        expected_message = transaction.message_data()
        raw_transaction = base64.b64encode(bytes(transaction)).decode("ascii")

        initiated = await self._initiate_transaction(raw_transaction)
        signed = await self._poll_signed_transaction(initiated)

        solana_transaction = signed.get("solanaTransaction")
        raw_signed = (
            solana_transaction.get("rawTransaction")
            if isinstance(solana_transaction, dict)
            else None
        )
        if not isinstance(raw_signed, str):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Utila signed transaction response missing solanaTransaction.rawTransaction",
            )
        signature = self._extract_signature_from_raw_transaction(raw_signed, expected_message)

        add_signature_to_transaction(transaction, public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        raise SignerError(
            SignerErrorCode.SIGNING_FAILED,
            "Utila sign_message is not supported for Solana wallets in this signer",
        )

    async def is_available(self) -> bool:
        try:
            await asyncio.wait_for(self._fetch_wallet(), AVAILABILITY_TIMEOUT_SECONDS)
        except (SignerError, asyncio.TimeoutError):
            return False
        return True


async def create_utila_signer(config: UtilaSignerConfig) -> UtilaSigner:
    """Create a ready-to-use Utila signer (awaits ``init()``)."""
    signer = UtilaSigner(config)
    await signer.init()
    return signer
