"""Para API signer integration."""

import asyncio
import logging
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

DEFAULT_API_BASE_URL = "https://api.getpara.com"
REQUEST_TIMEOUT_SECONDS = 30.0
AVAILABILITY_TIMEOUT_SECONDS = 5.0

SIGNATURE_HEX_LENGTH = 128

_logger = logging.getLogger("solana_keychain")


def _is_valid_uuid(value: str) -> bool:
    if len(value) != 36:
        return False
    if any(value[position] != "-" for position in (8, 13, 18, 23)):
        return False
    hex_chars = value.replace("-", "")
    return len(hex_chars) == 32 and all(c in "0123456789abcdefABCDEF" for c in hex_chars)


@dataclass
class ParaSignerConfig:
    """Configuration for a Para signer.

    ``api_key`` must be a Para secret key (``sk_`` prefix); ``wallet_id`` must be a
    canonical dashed UUID.
    """

    api_key: str = field(repr=False)
    wallet_id: str
    api_base_url: str = DEFAULT_API_BASE_URL
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class ParaSigner(SolanaSigner):
    """Signer backed by a Para-held wallet.

    ``init()`` must be awaited before use — it resolves the wallet's public key.
    ``create_para_signer()`` does this for you.
    """

    def __init__(self, config: ParaSignerConfig) -> None:
        if not config.api_key or not config.wallet_id:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "api_key and wallet_id must not be empty"
            )
        if not config.api_key.startswith("sk_"):
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, "api_key must be a Para secret key (starts with sk_)"
            )
        if not _is_valid_uuid(config.wallet_id):
            raise SignerError(SignerErrorCode.CONFIG_ERROR, "wallet_id must be a valid UUID")
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._api_key = config.api_key
        self._wallet_id = config.wallet_id
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return f"ParaSigner(pubkey={self._public_key})"

    async def init(self) -> None:
        """Resolve the wallet's public key. Must be awaited before signing."""
        wallet = await self._fetch_wallet()
        wallet_type = str(wallet.get("type", ""))
        if wallet_type.upper() != "SOLANA":
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, f"Expected SOLANA wallet, got: {wallet_type}"
            )
        status = str(wallet.get("status", ""))
        if status.upper() not in ("ACTIVE", "READY"):
            _logger.warning("Para wallet status is %r — signing may fail", status)
        address = wallet.get("address")
        if not isinstance(address, str) or not address:
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR,
                "Wallet does not have an address (may still be creating)",
            )
        try:
            self._public_key = Pubkey.from_string(address)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid Solana public key from Para API"
            ) from None

    def _initialized_pubkey(self) -> Pubkey:
        if self._public_key is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "ParaSigner is not initialized; call init() before signing",
            )
        return self._public_key

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    async def _fetch_wallet(self) -> dict[str, object]:
        url = f"{self._api_base_url}/v1/wallets/{quote(self._wallet_id, safe='')}"
        wallet = await fetch_signer_json(
            url=url,
            provider_name="Para",
            headers={"X-API-Key": self._api_key},
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            client=self._http_client,
        )
        if not isinstance(wallet, dict):
            raise SignerError(SignerErrorCode.REMOTE_API_ERROR, "Invalid Para wallet response")
        return wallet

    @staticmethod
    def _decode_hex_signature(hex_signature: str) -> Signature:
        stripped = hex_signature.removeprefix("0x")
        if len(stripped) != SIGNATURE_HEX_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Expected {SIGNATURE_HEX_LENGTH} hex chars (64 bytes), got {len(stripped)} chars",
            )
        try:
            signature_bytes = bytes.fromhex(stripped)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Failed to decode hex signature"
            ) from None
        try:
            return Signature.from_bytes(signature_bytes)
        except Exception:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Failed to parse signature") from None

    async def _sign_bytes(self, data: bytes) -> Signature:
        public_key = self._initialized_pubkey()
        url = f"{self._api_base_url}/v1/wallets/{quote(self._wallet_id, safe='')}/sign-raw"
        response = await fetch_signer_json(
            url=url,
            provider_name="Para",
            method="POST",
            headers={"X-API-Key": self._api_key},
            json_body={"data": data.hex(), "encoding": "hex"},
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            client=self._http_client,
        )
        hex_signature = response.get("signature") if isinstance(response, dict) else None
        if not isinstance(hex_signature, str):
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Missing signature in response")
        signature = self._decode_hex_signature(hex_signature)
        if not signature.verify(public_key, data):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Signature verification failed — the returned signature does not match "
                "the public key",
            )
        return signature

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        signature = await self._sign_bytes(transaction.message_data())
        add_signature_to_transaction(transaction, self._initialized_pubkey(), signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return await self._sign_bytes(message)

    async def is_available(self) -> bool:
        """Availability makes a network call bounded to 5 seconds; cache the result
        if frequent checks are needed."""
        try:
            wallet = await asyncio.wait_for(self._fetch_wallet(), AVAILABILITY_TIMEOUT_SECONDS)
        except (SignerError, asyncio.TimeoutError):
            # asyncio.TimeoutError: on 3.10 wait_for raises this distinct class;
            # from 3.11 it aliases the builtin, so one except covers both.
            return False
        wallet_type = str(wallet.get("type", ""))
        status = str(wallet.get("status", ""))
        return wallet_type.upper() == "SOLANA" and status.upper() in ("ACTIVE", "READY")


async def create_para_signer(config: ParaSignerConfig) -> ParaSigner:
    """Create a ready-to-use Para signer (awaits ``init()``)."""
    signer = ParaSigner(config)
    await signer.init()
    return signer
