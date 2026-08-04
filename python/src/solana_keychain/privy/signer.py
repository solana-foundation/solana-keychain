"""Privy API signer integration."""

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
from solana_keychain.privy.authorization import (
    DEFAULT_AUTHORIZATION_REQUEST_EXPIRY_MS,
    PrivyAuthorizationConfig,
    prepare_authorization_headers,
)

DEFAULT_API_BASE_URL = "https://api.privy.io/v1"


@dataclass
class PrivySignerConfig:
    """Configuration for a Privy signer.

    ``authorization_request_expiry_ms`` defaults to 15 minutes; set it to ``None``
    to omit ``privy-request-expiry`` from signed payloads and request headers.
    """

    app_id: str
    app_secret: str = field(repr=False)
    wallet_id: str
    api_base_url: str = DEFAULT_API_BASE_URL
    authorization_context: PrivyAuthorizationConfig | None = field(default=None, repr=False)
    authorization_request_expiry_ms: int | None = DEFAULT_AUTHORIZATION_REQUEST_EXPIRY_MS
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class PrivySigner(SolanaSigner):
    """Signer backed by a Privy-held wallet.

    ``init()`` must be awaited before use — it resolves the wallet's public key.
    ``create_privy_signer()`` does this for you.
    """

    def __init__(self, config: PrivySignerConfig) -> None:
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._app_id = config.app_id
        self._app_secret = config.app_secret
        self._wallet_id = config.wallet_id
        self._authorization_context = config.authorization_context
        self._authorization_request_expiry_ms = config.authorization_request_expiry_ms
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return f"PrivySigner(pubkey={self._public_key})"

    async def init(self) -> None:
        """Resolve the wallet's public key. Must be awaited before signing."""
        self._public_key = await self._fetch_public_key()

    def _initialized_pubkey(self) -> Pubkey:
        if self._public_key is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "PrivySigner is not initialized; call init() before signing",
            )
        return self._public_key

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    def _base_headers(self) -> dict[str, str]:
        credentials = base64.b64encode(f"{self._app_id}:{self._app_secret}".encode()).decode(
            "ascii"
        )
        return {"Authorization": f"Basic {credentials}", "privy-app-id": self._app_id}

    async def _fetch_public_key(self) -> Pubkey:
        url = f"{self._api_base_url}/wallets/{quote(self._wallet_id, safe='')}"
        wallet = await fetch_signer_json(
            url=url,
            provider_name="Privy",
            headers=self._base_headers(),
            client=self._http_client,
        )
        if not isinstance(wallet, dict):
            raise SignerError(SignerErrorCode.REMOTE_API_ERROR, "Invalid Privy wallet response")
        chain_type = wallet.get("chain_type")
        if chain_type != "solana":
            raise SignerError(
                SignerErrorCode.REMOTE_API_ERROR,
                f"Expected Solana wallet, got chain_type={chain_type}",
            )
        try:
            return Pubkey.from_string(wallet.get("address", ""))
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid public key from Privy API"
            ) from None

    async def _sign_bytes(self, message: bytes) -> Signature:
        public_key = self._initialized_pubkey()
        url = f"{self._api_base_url}/wallets/{quote(self._wallet_id, safe='')}/rpc"
        request = {
            "method": "signMessage",
            "chain_type": "solana",
            "params": {"message": base64.b64encode(message).decode("ascii"), "encoding": "base64"},
        }
        authorization_signature, request_expiry = prepare_authorization_headers(
            app_id=self._app_id,
            authorization_config=self._authorization_context,
            method="POST",
            url=url,
            body=request,
            request_expiry_ms=self._authorization_request_expiry_ms,
        )
        headers = self._base_headers()
        headers["Content-Type"] = "application/json"
        if authorization_signature is not None:
            headers["privy-authorization-signature"] = authorization_signature
        if request_expiry is not None:
            headers["privy-request-expiry"] = request_expiry

        response = await fetch_signer_json(
            url=url,
            provider_name="Privy",
            method="POST",
            headers=headers,
            json_body=request,
            client=self._http_client,
        )

        data = response.get("data") if isinstance(response, dict) else None
        signature_b64 = data.get("signature") if isinstance(data, dict) else None
        if not isinstance(signature_b64, str):
            raise SignerError(SignerErrorCode.REMOTE_API_ERROR, "No signature in Privy response")
        try:
            signature_bytes = base64.b64decode(signature_b64, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode base64 signature from Privy",
            ) from None
        try:
            signature = Signature.from_bytes(signature_bytes)
        except Exception:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Failed to parse signature") from None
        if not signature.verify(public_key, message):
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
        if self._public_key is None:
            return False
        try:
            return await self._fetch_public_key() == self._public_key
        except SignerError:
            return False


async def create_privy_signer(config: PrivySignerConfig) -> PrivySigner:
    """Create a ready-to-use Privy signer (awaits ``init()``)."""
    signer = PrivySigner(config)
    await signer.init()
    return signer
