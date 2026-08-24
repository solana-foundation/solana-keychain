"""Dfns Keys API signer integration."""

import json
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import assert_https_url, fetch_signer_json, normalize_base_url
from solana_keychain.core.signature_util import verify_returned_signature
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
    signed_message_bytes,
)
from solana_keychain.dfns.auth import sign_user_action

DEFAULT_API_BASE_URL = "https://api.dfns.io"


@dataclass
class DfnsSignerConfig:
    """Configuration for a Dfns signer.

    ``auth_token`` is a service-account or personal access token; ``cred_id`` and
    ``private_key_pem`` (Ed25519, P-256, or RSA) identify the credential used for
    User Action Signing.
    """

    auth_token: str = field(repr=False)
    cred_id: str
    private_key_pem: str = field(repr=False)
    wallet_id: str
    api_base_url: str = DEFAULT_API_BASE_URL
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class DfnsSigner(SolanaSigner):
    """Signer backed by a Dfns-held wallet.

    ``init()`` must be awaited before signing — it resolves the wallet's signing-key
    id and public key. ``create_dfns_signer()`` does this for you.
    """

    def __init__(self, config: DfnsSignerConfig) -> None:
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        self._api_base_url = api_base_url
        self._auth_token = config.auth_token
        self._cred_id = config.cred_id
        self._private_key_pem = config.private_key_pem
        self._wallet_id = config.wallet_id
        self._http_client = config.http_client
        self._key_id: str | None = None
        self._public_key: Pubkey | None = None

    def __repr__(self) -> str:
        return (
            f"DfnsSigner(pubkey={self._public_key}, wallet_id={self._wallet_id}, "
            f"key_id={self._key_id})"
        )

    async def _get_wallet(self) -> dict[str, object]:
        wallet = await fetch_signer_json(
            url=f"{self._api_base_url}/wallets/{quote(self._wallet_id, safe='')}",
            provider_name="Dfns",
            headers={"Authorization": f"Bearer {self._auth_token}"},
            client=self._http_client,
        )
        if not isinstance(wallet, dict):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse wallet response"
            )
        return wallet

    @staticmethod
    def _signing_key_fields(wallet: dict[str, object]) -> tuple[str, str, str, str]:
        signing_key = wallet.get("signingKey")
        if not isinstance(signing_key, dict):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse wallet response"
            )
        return (
            str(signing_key.get("id", "")),
            str(signing_key.get("scheme", "")),
            str(signing_key.get("curve", "")),
            str(signing_key.get("publicKey", "")),
        )

    async def init(self) -> None:
        """Resolve the wallet's signing-key id and public key. Must be awaited
        before signing."""
        wallet = await self._get_wallet()
        status = str(wallet.get("status", ""))
        if status != "Active":
            raise SignerError(SignerErrorCode.CONFIG_ERROR, f"Wallet is not active: {status}")
        key_id, scheme, curve, public_key_hex = self._signing_key_fields(wallet)
        if scheme != "EdDSA":
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, f"Unsupported key scheme: {scheme} (expected EdDSA)"
            )
        if curve != "ed25519":
            raise SignerError(
                SignerErrorCode.CONFIG_ERROR, f"Unsupported key curve: {curve} (expected ed25519)"
            )
        try:
            pubkey_bytes = bytes.fromhex(public_key_hex)
        except ValueError:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY, "Failed to decode hex public key"
            ) from None
        if len(pubkey_bytes) != 32:
            raise SignerError(
                SignerErrorCode.INVALID_PUBLIC_KEY,
                "Invalid public key length (expected 32 bytes)",
            )
        self._public_key = Pubkey.from_bytes(pubkey_bytes)
        self._key_id = key_id

    def _initialized(self) -> tuple[Pubkey, str]:
        if self._public_key is None or self._key_id is None:
            raise SignerError(
                SignerErrorCode.NOT_INITIALIZED,
                "DfnsSigner is not initialized; call init() before signing",
            )
        return self._public_key, self._key_id

    @property
    def pubkey(self) -> Pubkey:
        return self._initialized()[0]

    @staticmethod
    def _combine_signature(r_hex: str, s_hex: str) -> Signature:
        try:
            r_bytes = bytes.fromhex(r_hex.removeprefix("0x"))
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode signature r"
            ) from None
        try:
            s_bytes = bytes.fromhex(s_hex.removeprefix("0x"))
        except ValueError:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode signature s"
            ) from None
        signature_bytes = r_bytes + s_bytes
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Invalid signature length (expected {ED25519_SIGNATURE_LENGTH} bytes)",
            )
        return Signature.from_bytes(signature_bytes)

    async def _send_signature_request(self, request: dict[str, str]) -> Signature:
        _, key_id = self._initialized()
        http_path = f"/keys/{quote(key_id, safe='')}/signatures"
        body = json.dumps(request, separators=(",", ":"))

        user_action = await sign_user_action(
            api_base_url=self._api_base_url,
            auth_token=self._auth_token,
            cred_id=self._cred_id,
            private_key_pem=self._private_key_pem,
            http_method="POST",
            http_path=http_path,
            body=body,
            client=self._http_client,
        )

        response = await fetch_signer_json(
            url=f"{self._api_base_url}{http_path}",
            provider_name="Dfns",
            method="POST",
            headers={
                "Authorization": f"Bearer {self._auth_token}",
                "Content-Type": "application/json",
                "x-dfns-useraction": user_action,
            },
            content=body.encode(),
            client=self._http_client,
        )
        if not isinstance(response, dict):
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR, "Failed to parse signature response"
            )
        status = response.get("status")
        if status == "Failed":
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Dfns signing failed")
        if status != "Signed":
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Unexpected signature status: {status} (may require policy approval)",
            )
        components = response.get("signature")
        if (
            not isinstance(components, dict)
            or not isinstance(components.get("r"), str)
            or not isinstance(components.get("s"), str)
        ):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED, "Signature components missing from response"
            )
        return self._combine_signature(components["r"], components["s"])

    async def sign_message(self, message: bytes) -> Signature:
        public_key, _ = self._initialized()
        signature = await self._send_signature_request(
            {"kind": "Message", "message": f"0x{message.hex()}"}
        )
        return verify_returned_signature(signature, public_key, message)

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        public_key, _ = self._initialized()
        signature = await self._send_signature_request(
            {
                "kind": "Transaction",
                "transaction": f"0x{bytes(transaction).hex()}",
                "blockchainKind": "Solana",
            }
        )
        verify_returned_signature(signature, public_key, signed_message_bytes(transaction.message))
        add_signature_to_transaction(transaction, public_key, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def is_available(self) -> bool:
        try:
            wallet = await self._get_wallet()
            _, scheme, curve, _ = self._signing_key_fields(wallet)
        except SignerError:
            return False
        return (
            str(wallet.get("status", "")) == "Active" and scheme == "EdDSA" and curve == "ed25519"
        )


async def create_dfns_signer(config: DfnsSignerConfig) -> DfnsSigner:
    """Create a ready-to-use Dfns signer (awaits ``init()``)."""
    signer = DfnsSigner(config)
    await signer.init()
    return signer
