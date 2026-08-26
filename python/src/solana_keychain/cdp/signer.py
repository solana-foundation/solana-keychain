"""CDP (Coinbase Developer Platform) signer integration."""

import base64
from dataclasses import dataclass, field
from typing import Any

try:
    import base58
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.cdp requires the cdp extra: pip install 'solana-keychain[cdp]'"
    ) from error

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.cdp.jwt import create_auth_jwt, create_wallet_jwt
from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import (
    assert_https_url,
    fetch_signer_json,
    normalize_base_url,
    probe_availability,
)
from solana_keychain.core.signature_util import (
    extract_and_verify_returned_signature,
    verify_returned_signature,
)
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.core.wallet_jwt import extract_host

DEFAULT_API_BASE_URL = "https://api.cdp.coinbase.com"
BASE_PATH = "/platform/v2/solana/accounts"


@dataclass
class CdpSignerConfig:
    """Configuration for a CDP signer.

    ``api_key_secret`` is the base64 Ed25519 API private key (seed ‖ pubkey);
    ``wallet_secret`` is the base64 PKCS8 DER P-256 wallet key used for the
    ``X-Wallet-Auth`` token on write endpoints; ``address`` is the base58 Solana
    account address managed by CDP.
    """

    api_key_id: str
    api_key_secret: str = field(repr=False)
    wallet_secret: str = field(repr=False)
    address: str
    api_base_url: str = DEFAULT_API_BASE_URL
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class CdpSigner(SolanaSigner):
    """Signer backed by a CDP-managed Solana account.

    ``sign_message`` requires UTF-8 payloads — the sign-message endpoint takes a
    string, so arbitrary non-UTF-8 bytes are rejected.
    """

    def __init__(self, config: CdpSignerConfig) -> None:
        for name, value in (
            ("api_key_id", config.api_key_id),
            ("api_key_secret", config.api_key_secret),
            ("wallet_secret", config.wallet_secret),
            ("address", config.address),
        ):
            if not value:
                raise SignerError(SignerErrorCode.CONFIG_ERROR, f"{name} must not be empty")
        try:
            self._pubkey = Pubkey.from_string(config.address)
        except Exception:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, f"Invalid Solana address: {config.address}"
            ) from None
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._api_host = extract_host(api_base_url, "CDP")
        self._api_key_id = config.api_key_id
        self._api_key_secret = config.api_key_secret
        self._wallet_secret = config.wallet_secret
        self._http_client = config.http_client

    def __repr__(self) -> str:
        return f"CdpSigner(pubkey={self._pubkey}, api_base_url={self._api_base_url})"

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    async def _post_signed(self, path: str, body: dict[str, Any]) -> Any:
        auth_token = create_auth_jwt(
            self._api_key_id, self._api_key_secret, self._api_host, "POST", path
        )
        wallet_token = create_wallet_jwt(self._wallet_secret, self._api_host, "POST", path, body)
        return await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="CDP",
            method="POST",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
                "X-Wallet-Auth": wallet_token,
            },
            json_body=body,
            client=self._http_client,
        )

    async def sign_message(self, message: bytes) -> Signature:
        try:
            message_str = message.decode("utf-8")
        except UnicodeDecodeError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "CDP signMessage requires UTF-8; non-UTF-8 bytes are not supported",
            ) from None
        path = f"{BASE_PATH}/{self._pubkey}/sign/message"
        response = await self._post_signed(path, {"message": message_str})
        signature_b58 = response.get("signature") if isinstance(response, dict) else None
        if not isinstance(signature_b58, str):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse CDP sign_message response"
            )
        try:
            signature_bytes = base58.b58decode(signature_b58)
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode base58 signature from CDP",
            ) from None
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Invalid signature length from CDP (expected {ED25519_SIGNATURE_LENGTH} bytes)",
            )
        signature = Signature.from_bytes(signature_bytes)
        return verify_returned_signature(signature, self._pubkey, message)

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        message_data = signed_message_bytes(transaction.message)
        path = f"{BASE_PATH}/{self._pubkey}/sign/transaction"
        encoded_tx = base64.b64encode(bytes(transaction)).decode("ascii")
        response = await self._post_signed(path, {"transaction": encoded_tx})

        signed_b64 = response.get("signedTransaction") if isinstance(response, dict) else None
        if not isinstance(signed_b64, str):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to parse CDP sign_transaction response",
            )
        try:
            signed_bytes = base64.b64decode(signed_b64, validate=True)
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode base64 signed transaction from CDP",
            ) from None
        signature = extract_and_verify_returned_signature(
            signed_bytes, self._pubkey, message_data, "CDP"
        )
        add_signature_to_transaction(transaction, self._pubkey, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def is_available(self) -> bool:
        path = f"{BASE_PATH}/{self._pubkey}"

        async def probe() -> bool:
            auth_token = create_auth_jwt(
                self._api_key_id, self._api_key_secret, self._api_host, "GET", path
            )
            await fetch_signer_json(
                url=f"{self._api_base_url}{path}",
                provider_name="CDP",
                headers={"Authorization": f"Bearer {auth_token}"},
                client=self._http_client,
            )
            return True

        return await probe_availability(probe)


async def create_cdp_signer(config: CdpSignerConfig) -> CdpSigner:
    """Create a ready-to-use CDP signer."""
    return CdpSigner(config)
