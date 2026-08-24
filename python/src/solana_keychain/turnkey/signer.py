"""Turnkey API signer integration."""

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.turnkey requires the turnkey extra: pip install 'solana-keychain[turnkey]'"
    ) from error

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.http import assert_https_url, fetch_signer_json, normalize_base_url
from solana_keychain.core.signature_util import verify_returned_signature
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    add_signature_to_transaction,
    classify_signed_transaction,
    get_signing_keypair_position,
    serialize_transaction,
    signed_message_bytes,
)

DEFAULT_API_BASE_URL = "https://api.turnkey.com"

SIGNATURE_COMPONENT_LENGTH = 32
P256_PRIVATE_KEY_LENGTH = 32
P256_COMPRESSED_PUBLIC_KEY_LENGTH = 33


def _validate_api_key_material(private_key_hex: str, public_key_hex: str) -> None:
    """Both keys must be valid hex; the public key must be a 33-byte compressed
    P-256 point that decompresses to a valid curve point; the private key must be
    32 bytes."""
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        private_key_bytes = bytes.fromhex(private_key_hex)
    except ValueError:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, "Turnkey API keys must be valid hex strings"
        ) from None
    if len(public_key_bytes) != P256_COMPRESSED_PUBLIC_KEY_LENGTH:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            f"Public key must be {P256_COMPRESSED_PUBLIC_KEY_LENGTH} bytes "
            f"(compressed P-256 format), got {len(public_key_bytes)}",
        )
    if len(private_key_bytes) != P256_PRIVATE_KEY_LENGTH:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR,
            f"Private key must be {P256_PRIVATE_KEY_LENGTH} bytes, got {len(private_key_bytes)}",
        )
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
    except Exception:
        raise SignerError(
            SignerErrorCode.CONFIG_ERROR, "Public key is not a valid P-256 point"
        ) from None


@dataclass
class TurnkeySignerConfig:
    """Configuration for a Turnkey signer.

    ``api_public_key``/``api_private_key`` are the hex-encoded P-256 API key pair used
    to stamp requests. ``private_key_id`` identifies the Turnkey-held Solana key to
    sign with, and ``public_key`` is its base58 Solana public key.
    """

    api_public_key: str
    api_private_key: str = field(repr=False)
    organization_id: str
    private_key_id: str
    public_key: str
    api_base_url: str = DEFAULT_API_BASE_URL
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)


class TurnkeySigner(SolanaSigner):
    """Signer backed by a Turnkey-held Solana private key."""

    def __init__(self, config: TurnkeySignerConfig) -> None:
        try:
            self._pubkey = Pubkey.from_string(config.public_key)
        except Exception:
            raise SignerError(SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid public key") from None
        api_base_url = normalize_base_url(config.api_base_url)
        assert_https_url(api_base_url, "api_base_url")
        _validate_api_key_material(config.api_private_key, config.api_public_key)
        self._api_base_url = api_base_url
        self._api_public_key = config.api_public_key
        self._api_private_key = config.api_private_key
        self._organization_id = config.organization_id
        self._private_key_id = config.private_key_id
        self._http_client = config.http_client

    def __repr__(self) -> str:
        return f"TurnkeySigner(pubkey={self._pubkey})"

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    def _create_stamp(self, body: str) -> str:
        """Build the X-Stamp header: a P-256 ECDSA signature over the exact request
        body bytes, DER-encoded, wrapped in a base64url JSON envelope."""
        try:
            signing_key = ec.derive_private_key(
                int.from_bytes(bytes.fromhex(self._api_private_key), "big"), ec.SECP256R1()
            )
        except Exception:
            raise SignerError(SignerErrorCode.INVALID_PRIVATE_KEY, "Invalid signing key") from None
        der_signature = signing_key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))
        stamp = json.dumps(
            {
                "publicKey": self._api_public_key,
                "scheme": "SIGNATURE_SCHEME_TK_API_P256",
                "signature": der_signature.hex(),
            },
            separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(stamp.encode()).rstrip(b"=").decode("ascii")

    async def _post_stamped(self, path: str, request: dict[str, Any]) -> Any:
        body = json.dumps(request, separators=(",", ":"))
        return await fetch_signer_json(
            url=f"{self._api_base_url}{path}",
            provider_name="Turnkey",
            method="POST",
            headers={"Content-Type": "application/json", "X-Stamp": self._create_stamp(body)},
            content=body.encode(),
            client=self._http_client,
        )

    @staticmethod
    def _assemble_signature(r_hex: str, s_hex: str) -> bytes:
        """Concatenate the r and s components, left-padding each to 32 bytes.

        Turnkey may return components with leading zero bytes trimmed; a raw
        concatenation would misalign the 64-byte Ed25519 signature.
        """
        try:
            r_bytes = bytes.fromhex(r_hex)
        except ValueError:
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode r") from None
        try:
            s_bytes = bytes.fromhex(s_hex)
        except ValueError:
            raise SignerError(SignerErrorCode.SERIALIZATION_ERROR, "Failed to decode s") from None
        if len(r_bytes) > SIGNATURE_COMPONENT_LENGTH or len(s_bytes) > SIGNATURE_COMPONENT_LENGTH:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Invalid signature component length")
        return r_bytes.rjust(SIGNATURE_COMPONENT_LENGTH, b"\x00") + s_bytes.rjust(
            SIGNATURE_COMPONENT_LENGTH, b"\x00"
        )

    async def _sign_bytes(self, message: bytes) -> Signature:
        request = {
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
            "timestampMs": str(int(time.time() * 1000)),
            "organizationId": self._organization_id,
            "parameters": {
                "signWith": self._private_key_id,
                "payload": message.hex(),
                "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
                "hashFunction": "HASH_FUNCTION_NOT_APPLICABLE",
            },
        }
        response = await self._post_stamped("/public/v1/submit/sign_raw_payload", request)

        result = self._completed_activity_result(response)
        sign_result = result.get("signRawPayloadResult") if isinstance(result, dict) else None
        if (
            not isinstance(sign_result, dict)
            or not isinstance(sign_result.get("r"), str)
            or not isinstance(sign_result.get("s"), str)
        ):
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Invalid response from Turnkey API")

        signature = Signature.from_bytes(
            self._assemble_signature(sign_result["r"], sign_result["s"])
        )
        return verify_returned_signature(signature, self._pubkey, message)

    @staticmethod
    def _completed_activity_result(response: Any) -> Any:
        activity = response.get("activity") if isinstance(response, dict) else None
        status = activity.get("status") if isinstance(activity, dict) else None
        if status != "ACTIVITY_STATUS_COMPLETED":
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Turnkey activity is not completed (status: {status or '<missing>'})",
            )
        return activity.get("result") if isinstance(activity, dict) else None

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        """Sign via the ``sign_transaction`` activity, submitting the full wire
        transaction so Turnkey's policy engine can evaluate ``solana.tx``
        conditions. Policies must allow ``ACTIVITY_TYPE_SIGN_TRANSACTION_V2``."""
        request = {
            "type": "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
            "timestampMs": str(int(time.time() * 1000)),
            "organizationId": self._organization_id,
            "parameters": {
                "signWith": self._private_key_id,
                "type": "TRANSACTION_TYPE_SOLANA",
                "unsignedTransaction": bytes(transaction).hex(),
            },
        }
        response = await self._post_stamped("/public/v1/submit/sign_transaction", request)

        result = self._completed_activity_result(response)
        sign_result = result.get("signTransactionResult") if isinstance(result, dict) else None
        signed_hex = sign_result.get("signedTransaction") if isinstance(sign_result, dict) else None
        if not isinstance(signed_hex, str):
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "Invalid response from Turnkey API")
        try:
            signed = VersionedTransaction.from_bytes(bytes.fromhex(signed_hex))
        except Exception:
            raise SignerError(
                SignerErrorCode.SERIALIZATION_ERROR,
                "Failed to decode signed transaction returned by Turnkey",
            ) from None

        position = get_signing_keypair_position(signed, self._pubkey)
        signatures = signed.signatures
        if position >= len(signatures):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Turnkey signature slot missing from returned transaction",
            )
        signature = signatures[position]
        verify_returned_signature(
            signature, self._pubkey, signed_message_bytes(transaction.message)
        )
        add_signature_to_transaction(transaction, self._pubkey, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return await self._sign_bytes(message)

    async def is_available(self) -> bool:
        try:
            await self._post_stamped(
                "/public/v1/query/whoami", {"organizationId": self._organization_id}
            )
        except SignerError:
            return False
        return True


async def create_turnkey_signer(config: TurnkeySignerConfig) -> TurnkeySigner:
    """Create a ready-to-use Turnkey signer."""
    return TurnkeySigner(config)
