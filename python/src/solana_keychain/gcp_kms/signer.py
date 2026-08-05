"""Google Cloud KMS signer integration using EdDSA (Ed25519) signing."""

from dataclasses import dataclass, field
from typing import Any

try:
    from google.api_core.exceptions import GoogleAPIError
    from google.auth.exceptions import GoogleAuthError
    from google.cloud import kms_v1
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.gcp_kms requires the gcp-kms extra: pip install 'solana-keychain[gcp-kms]'"
    ) from error

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from solana_keychain.core.errors import SignerError, SignerErrorCode
from solana_keychain.core.signer import SignedTransaction, SolanaSigner
from solana_keychain.core.transaction_util import (
    ED25519_SIGNATURE_LENGTH,
    add_signature_to_transaction,
    classify_signed_transaction,
    serialize_transaction,
)

EC_SIGN_ED25519 = kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519


@dataclass
class GcpKmsSignerConfig:
    """Configuration for a GCP KMS signer.

    ``key_name`` is the full resource name of the crypto key version, e.g.
    ``projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1``, and must
    reference an ``EC_SIGN_ED25519`` key. ``public_key`` is the base58 Solana public
    key corresponding to that key. ``client`` accepts a pre-configured
    ``KeyManagementServiceAsyncClient`` (custom credentials, endpoint, or transport).
    """

    key_name: str
    public_key: str
    client: Any | None = field(default=None, repr=False)


class GcpKmsSigner(SolanaSigner):
    """Signer backed by a Google Cloud KMS Ed25519 key."""

    def __init__(self, config: GcpKmsSignerConfig) -> None:
        try:
            self._pubkey = Pubkey.from_string(config.public_key)
        except Exception:
            raise SignerError(SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid public key") from None
        self._key_name = config.key_name
        self._client = (
            config.client if config.client is not None else kms_v1.KeyManagementServiceAsyncClient()
        )

    def __repr__(self) -> str:
        return f"GcpKmsSigner(key_name={self._key_name}, pubkey={self._pubkey})"

    @property
    def key_name(self) -> str:
        return self._key_name

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    async def _sign_bytes(self, message: bytes) -> Signature:
        # EC_SIGN_ED25519 operates in PureEdDSA mode: the request carries the raw
        # data, never a digest.
        try:
            response = await self._client.asymmetric_sign(
                request={"name": self._key_name, "data": message}
            )
        except (GoogleAPIError, GoogleAuthError) as error:
            raise SignerError(
                SignerErrorCode.REMOTE_API_ERROR, f"GCP KMS Sign operation failed: {error}"
            ) from None
        signature_bytes = bytes(response.signature)
        if not signature_bytes:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "No signature in GCP KMS response")
        if len(signature_bytes) != ED25519_SIGNATURE_LENGTH:
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                f"Invalid signature length: expected {ED25519_SIGNATURE_LENGTH} bytes, "
                f"got {len(signature_bytes)}",
            )
        signature = Signature.from_bytes(signature_bytes)
        if not signature.verify(self._pubkey, message):
            raise SignerError(
                SignerErrorCode.SIGNING_FAILED,
                "Signature verification failed — the returned signature does not match "
                "the public key",
            )
        return signature

    async def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        signature = await self._sign_bytes(transaction.message_data())
        add_signature_to_transaction(transaction, self._pubkey, signature)
        return classify_signed_transaction(
            transaction, serialize_transaction(transaction), signature
        )

    async def sign_message(self, message: bytes) -> Signature:
        return await self._sign_bytes(message)

    async def is_available(self) -> bool:
        try:
            response = await self._client.get_public_key(request={"name": self._key_name})
        except (GoogleAPIError, GoogleAuthError):
            return False
        return bool(response.algorithm == EC_SIGN_ED25519)


async def create_gcp_kms_signer(config: GcpKmsSignerConfig) -> GcpKmsSigner:
    """Create a ready-to-use GCP KMS signer.

    The client is constructed on the event loop: the gRPC async transport binds to
    the running loop, so construction must not be moved to a worker thread.
    """
    return GcpKmsSigner(config)
