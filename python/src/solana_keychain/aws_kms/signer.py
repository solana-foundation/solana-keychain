"""AWS KMS signer integration using EdDSA (Ed25519) signing."""

import asyncio
from dataclasses import dataclass, field
from typing import Any

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError as error:  # pragma: no cover
    raise ImportError(
        "solana_keychain.aws_kms requires the aws-kms extra: pip install 'solana-keychain[aws-kms]'"
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

AWS_KMS_SIGNING_ALGORITHM = "ED25519_SHA_512"
AWS_KMS_KEY_SPEC = "ECC_NIST_EDWARDS25519"
AWS_KMS_KEY_USAGE = "SIGN_VERIFY"


@dataclass
class AwsKmsSignerConfig:
    """Configuration for an AWS KMS signer.

    ``key_id`` is a KMS key ID, ARN, or alias and must reference an
    ``ECC_NIST_EDWARDS25519`` key. ``public_key`` is the base58 Solana public key
    corresponding to that KMS key. ``region`` falls back to the default AWS config
    chain when unset. ``client`` accepts a pre-configured KMS client (custom
    credentials, endpoint, or retry policy); when set, ``region`` is ignored.
    """

    key_id: str
    public_key: str
    region: str | None = None
    client: Any | None = field(default=None, repr=False)


class AwsKmsSigner(SolanaSigner):
    """Signer backed by an AWS KMS Ed25519 key."""

    def __init__(self, config: AwsKmsSignerConfig) -> None:
        try:
            self._pubkey = Pubkey.from_string(config.public_key)
        except Exception:
            raise SignerError(SignerErrorCode.INVALID_PUBLIC_KEY, "Invalid public key") from None
        self._key_id = config.key_id
        self._region = config.region
        self._client = (
            config.client
            if config.client is not None
            else boto3.client("kms", region_name=config.region)
        )

    def __repr__(self) -> str:
        return f"AwsKmsSigner(key_id={self._key_id}, pubkey={self._pubkey}, region={self._region})"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def pubkey(self) -> Pubkey:
        return self._pubkey

    async def _sign_bytes(self, message: bytes) -> Signature:
        def sign_call() -> Any:
            return self._client.sign(
                KeyId=self._key_id,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=AWS_KMS_SIGNING_ALGORITHM,
            )

        try:
            response = await asyncio.to_thread(sign_call)
        except (BotoCoreError, ClientError) as error:
            raise SignerError(
                SignerErrorCode.REMOTE_API_ERROR, f"AWS KMS Sign operation failed: {error}"
            ) from None
        signature_bytes = response.get("Signature")
        if not signature_bytes:
            raise SignerError(SignerErrorCode.SIGNING_FAILED, "No signature in AWS KMS response")
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
        def describe_call() -> Any:
            return self._client.describe_key(KeyId=self._key_id)

        try:
            response = await asyncio.to_thread(describe_call)
        except (BotoCoreError, ClientError):
            return False
        metadata = response.get("KeyMetadata")
        if not isinstance(metadata, dict):
            return False
        return (
            metadata.get("KeySpec") == AWS_KMS_KEY_SPEC
            and metadata.get("Enabled") is True
            and metadata.get("KeyUsage") == AWS_KMS_KEY_USAGE
        )


async def create_aws_kms_signer(config: AwsKmsSignerConfig) -> AwsKmsSigner:
    """Create a ready-to-use AWS KMS signer.

    Construction runs in a worker thread: building the client can read AWS config
    files or query instance metadata, which must not block the event loop.
    """
    return await asyncio.to_thread(AwsKmsSigner, config)
