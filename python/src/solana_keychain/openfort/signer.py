"""Openfort backend wallet signer. The private key lives in Openfort's TEE and is
never exposed; message bytes are signed as-is (no hashing) and returned as a 64-byte
Ed25519 signature."""

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
from solana_keychain.openfort.jwt import create_wallet_jwt, extract_host

DEFAULT_API_BASE_URL = "https://api.openfort.io"
ACCOUNTS_PATH = "/v2/accounts"
BACKEND_PATH = "/v2/accounts/backend"

ED25519_SIGNATURE_LENGTH = 64


@dataclass
class OpenfortSignerConfig:
    """Configuration for an Openfort signer.

    ``secret_key`` is the project secret key (``sk_live_*``/``sk_test_*``);
    ``account_id`` the backend wallet account id (``acc_<uuid>``);
    ``wallet_secret`` the dashboard-issued ECDSA P-256 key that signs the
    ``x-wallet-auth`` JWT, as bare base64 PKCS8 DER or full PEM.
    """

    secret_key: str = field(repr=False)
    account_id: str
    wallet_secret: str = field(repr=False)
    api_base_url: str = DEFAULT_API_BASE_URL
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class OpenfortSigner(SolanaSigner):
    """Signer backed by an Openfort backend wallet.

    ``init()`` must be awaited before signing — it resolves the wallet's Solana
    address. ``create_openfort_signer()`` does this for you.
    """

    def __init__(self, config: OpenfortSignerConfig) -> None:
        for name, value in (
            ("secret_key", config.secret_key),
            ("account_id", config.account_id),
            ("wallet_secret", config.wallet_secret),
        ):
            if not value:
                raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{name} must not be empty")
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._api_host = extract_host(api_base_url)
        self._secret_key = config.secret_key
        self._account_id = config.account_id
        self._wallet_secret = config.wallet_secret
        self._http_client = config.http_client
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return (
            f"OpenfortSigner(account_id={self._account_id}, pubkey={self._public_key}, "
            f"api_base_url={self._api_base_url})"
        )

    def _account_path(self) -> str:
        return f"{ACCOUNTS_PATH}/{quote(self._account_id, safe='')}"

    def _sign_path(self) -> str:
        return f"{BACKEND_PATH}/{quote(self._account_id, safe='')}/sign"

    async def _fetch_public_key(self) -> Pubkey:
        response = await fetch_signer_json(
            url=f"{self._api_base_url}{self._account_path()}",
            provider_name="Openfort",
            headers={"Authorization": f"Bearer {self._secret_key}"},
            client=self._http_client,
        )
        address = response.get("address") if isinstance(response, dict) else None
        if not isinstance(address, str):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse Openfort account response"
            )
        try:
            return Pubkey.from_string(address)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                f"Openfort returned non-Solana address for {self._account_id}: "
                "ensure the account is on an SVM chain",
            ) from None

    async def init(self) -> None:
        """Resolve the wallet's Solana address. Must be awaited before signing."""
        self._public_key = await self._fetch_public_key()

    def _initialized_pubkey(self) -> Pubkey:
        if self._public_key is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "OpenfortSigner is not initialized; call init() before signing",
            )
        return self._public_key

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized_pubkey()

    async def _sign_bytes(self, message: bytes) -> Signature:
        public_key = self._initialized_pubkey()
        path = self._sign_path()
        body = {"data": f"0x{message.hex()}"}
        wallet_token = create_wallet_jwt(self._wallet_secret, self._api_host, "POST", path, body)
        response = await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Openfort",
            method="POST",
            headers={
                "Authorization": f"Bearer {self._secret_key}",
                "Content-Type": "application/json",
                "x-wallet-auth": wallet_token,
            },
            json_body=body,
            client=self._http_client,
        )
        signature_hex = response.get("signature") if isinstance(response, dict) else None
        if not isinstance(signature_hex, str):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse Openfort sign response"
            )
        try:
            signature_bytes = bytes.fromhex(signature_hex.removeprefix("0x"))
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to hex-decode Openfort signature"
            ) from None
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Invalid signature length from Openfort "
                f"(expected {ED25519_SIGNATURE_LENGTH} bytes)",
            )
        signature = Signature.from_bytes(signature_bytes)
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


async def create_openfort_signer(config: OpenfortSignerConfig) -> OpenfortSigner:
    """Create a ready-to-use Openfort signer (awaits ``init()``)."""
    signer = OpenfortSigner(config)
    await signer.init()
    return signer
